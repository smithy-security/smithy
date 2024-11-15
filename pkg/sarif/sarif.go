package sarif

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/package-url/packageurl-go"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
)

const (
	ExtraContextLanguageUnspecified ExtraContextLanguage = "unspecified"
	ExtraContextLanguagePython      ExtraContextLanguage = "python"
	ExtraContextLanguageJS          ExtraContextLanguage = "javascript"
)

type (
	// SmithyIssueCollection represents all the findings in a single Sarif file converted to smithy format.
	SmithyIssueCollection struct {
		ToolName string
		Issues   []*v1.Issue
	}

	ExtraContextLanguage string
)

var extraCtxLangToPURLNS = map[ExtraContextLanguage]string{
	ExtraContextLanguagePython: "pypi",
	ExtraContextLanguageJS:     "npm",
}

// FromSmithyEnrichedIssuesRun transforms a set of LaunchToolResponse to ONE sarif document with
// one run per launch tool response, by default it skips duplicates unless reportDuplicates is set
// to true.
func FromSmithyEnrichedIssuesRun(responses []*v1.EnrichedLaunchToolResponse, reportDuplicates bool) (*sarif.Report, error) {
	// if you are not ignoring duplicates use resultProvenance in each message to mark duplicates
	// annotations become attachments in each findings with the description the json of the label
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return &sarif.Report{}, err
	}

	for _, enrichedResponse := range responses {
		tool := sarif.NewSimpleTool(enrichedResponse.GetOriginalResults().GetToolName())
		run := sarif.NewRun(*tool)
		ad := sarif.NewRunAutomationDetails()
		ad = ad.WithGUID(enrichedResponse.GetOriginalResults().GetScanInfo().GetScanUuid())
		ad = ad.WithID(enrichedResponse.GetOriginalResults().GetScanInfo().GetScanUuid())
		ad = ad.WithDescriptionText(enrichedResponse.GetOriginalResults().GetScanInfo().GetScanStartTime().AsTime().Format(time.RFC3339))

		run.AutomationDetails = ad
		var sarifResults []*sarif.Result

		for _, issue := range enrichedResponse.Issues {
			// TODO(#119): improve this to avoid O(n^2)
			rule, err := run.GetRuleById(issue.RawIssue.Type)
			if err != nil {
				rule = run.AddRule(issue.RawIssue.Type)
			}
			res, err := smithyIssueToSarif(issue.RawIssue, rule)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			attachments := res.Attachments
			if issue.Count > 1 {
				if reportDuplicates {
					res.Provenance = sarif.NewResultProvenance()
					firstSeen := issue.FirstSeen.AsTime()
					res.Provenance.WithFirstDetectionTimeUTC(&firstSeen)
					attachments = append(attachments, sarif.NewAttachment().WithDescription(sarif.NewMessage().WithText(fmt.Sprintf("Duplicate.Count:%d", issue.Count))))
				} else {
					log.Printf("Issue %s is duplicate and we have been instructed to ignore it", issue.Hash)
					continue
				}
			}
			attachments = append(attachments, sarif.NewAttachment().WithDescription(sarif.NewMessage().WithText(fmt.Sprintf("False Positive:%t", issue.FalsePositive))))
			attachments = append(attachments, sarif.NewAttachment().WithDescription(sarif.NewMessage().WithText(fmt.Sprintf("Hash:%s", issue.Hash))))
			for key, value := range issue.Annotations {
				attachments = append(attachments, sarif.NewAttachment().WithDescription(sarif.NewMessage().WithText(fmt.Sprintf("%s:%s", key, value))))
			}
			res = res.WithAttachments(attachments)
			sarifResults = append(sarifResults, res)
		}
		run.WithResults(sarifResults)
		sarifReport.AddRun(run)
	}
	return sarifReport, nil
}

// FromSmithyRawIssuesRun accepts a set of Smithy LaunchToolResponses and transforms them to a Sarif file.
func FromSmithyRawIssuesRun(responses []*v1.LaunchToolResponse) (*sarif.Report, error) {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return &sarif.Report{}, err
	}
	for _, tr := range responses {
		tool := sarif.NewSimpleTool(tr.GetToolName())
		run := sarif.NewRun(*tool)

		ad := sarif.NewRunAutomationDetails()
		ad = ad.WithGUID(tr.GetScanInfo().GetScanUuid())
		ad = ad.WithID(tr.GetScanInfo().GetScanUuid())
		ad = ad.WithDescriptionText(fmt.Sprintf("%v", tr.GetScanInfo().GetScanStartTime().AsTime().Format(time.RFC3339)))
		run.AutomationDetails = ad

		var sarifResults []*sarif.Result
		for _, issue := range tr.Issues {
			rule, err := run.GetRuleById(issue.Type)
			if err != nil {
				rule = run.AddRule(issue.Type)
			}
			newResults, err := smithyIssueToSarif(issue, rule)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			sarifResults = append(sarifResults, newResults)
		}
		run.WithResults(sarifResults)
		sarifReport.AddRun(run)
	}

	return sarifReport, nil
}

func removeSmithyInternalPath(target string) string {
	return strings.Replace(target, producers.SourceDir, "", 1)
}

func smithyIssueToSarif(issue *v1.Issue, rule *sarif.ReportingDescriptor) (*sarif.Result, error) {
	sarifResults := sarif.NewRuleResult(rule.ID)
	loc := sarif.Location{}
	physicalLocation := sarif.PhysicalLocation{}
	artifactLocation := sarif.ArtifactLocation{}
	_, err := url.ParseRequestURI(removeSmithyInternalPath(issue.Target))
	if err != nil {
		return &sarif.Result{}, fmt.Errorf("issue titled '%s' targets '%s' which is not a valid URI, skipping", issue.Title, issue.Target)
	}
	artifactLocation.WithUri(removeSmithyInternalPath(issue.Target))
	physicalLocation.WithArtifactLocation(&artifactLocation)
	loc.WithPhysicalLocation(&physicalLocation)
	sarifResults.WithLocations([]*sarif.Location{&loc})
	sarifResults.WithLevel(severityToLevel(issue.Severity))

	message := sarif.NewMessage()
	message.WithText(issue.Description)
	sarifResults.WithMessage(message.WithText(issue.Description))
	var attachments []*sarif.Attachment

	confidence := fmt.Sprintf("Confidence:%s", issue.Confidence)
	attachments = append(attachments, &sarif.Attachment{Description: &sarif.Message{Text: &confidence}})

	if issue.GetSource() != "" {
		src := fmt.Sprintf("Source:%s", issue.GetSource())
		attachments = append(attachments, &sarif.Attachment{Description: &sarif.Message{Text: &src}})
	}
	if issue.GetCvss() != 0 {
		cvss := fmt.Sprintf("CVSS:%f", issue.GetCvss())
		attachments = append(attachments, &sarif.Attachment{Description: &sarif.Message{Text: &cvss}})
	}
	if issue.GetCve() != "" {
		cve := issue.GetCve()
		attachments = append(attachments, &sarif.Attachment{Description: &sarif.Message{Text: &cve}})
	}
	sarifResults.WithAttachments(attachments)
	return sarifResults, nil
}

// ToSmithy accepts a sarif file and transforms each run to SmithyIssueCollection ready to be written to a results file.
func ToSmithy(inFile string, language ExtraContextLanguage) ([]*SmithyIssueCollection, error) {
	issueCollection := []*SmithyIssueCollection{}
	inSarif, err := sarif.FromString(inFile)
	if err != nil {
		return issueCollection, err
	}
	for _, run := range inSarif.Runs {
		tool := run.Tool.Driver.Name
		rules := map[string]*sarif.ReportingDescriptor{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}

		issues, err := parseOut(*run, rules, tool, language)
		if err != nil {
			return nil, errors.Errorf("unexpected parse errors: %w", err)
		}

		if len(issues) == 0 {
			continue
		}

		issueCollection = append(issueCollection, &SmithyIssueCollection{
			ToolName: tool,
			Issues:   issues,
		})
	}
	return issueCollection, err
}

// parseOut parses a sarif report by extracting physical and logical targets from it
// and generating issues.
func parseOut(
	run sarif.Run,
	rules map[string]*sarif.ReportingDescriptor,
	toolName string,
	lang ExtraContextLanguage,
) ([]*v1.Issue, error) {
	var (
		issues   = make([]*v1.Issue, 0)
		parseErr error
	)

	for _, res := range run.Results {
		for _, loc := range res.Locations {

			targets, err := parseTargets(loc, lang)
			if err != nil {
				parseErr = errors.Join(parseErr, err)
			}

			for _, target := range targets {
				issues = addIssue(rules, issues, target, toolName, res)
			}

		}
	}

	return issues, parseErr
}

func addIssue(rules map[string]*sarif.ReportingDescriptor, issues []*v1.Issue, target, toolName string, res *sarif.Result) []*v1.Issue {
	var description string

	rule, ok := rules[*res.RuleID]
	if !ok {
		log.Printf("could not find rule with id %s, double check tool %s output contains a tool.driver.rules section ", *res.RuleID, toolName)
		description = fmt.Sprintf("Message: %s", *res.Message.Text)
	} else {
		ruleInfo, _ := json.Marshal(rule)
		description = fmt.Sprintf("MatchedRule: %s \n Message: %s", ruleInfo, *res.Message.Text)
	}
	issues = append(issues, &v1.Issue{
		Target:      target,
		Title:       *res.Message.Text,
		Description: description,
		Type:        *res.RuleID,
		Severity:    levelToSeverity(*res.Level),
		Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
	})

	return issues
}

// levelToSeverity transforms error, warning and note levels to high, medium and low respectively.
func levelToSeverity(level string) v1.Severity {
	if level == LevelError {
		return v1.Severity_SEVERITY_HIGH
	} else if level == LevelWarning {
		return v1.Severity_SEVERITY_MEDIUM
	}
	return v1.Severity_SEVERITY_INFO
}

func severityToLevel(severity v1.Severity) string {
	switch severity {
	case v1.Severity_SEVERITY_CRITICAL:
		return LevelError
	case v1.Severity_SEVERITY_HIGH:
		return LevelError
	case v1.Severity_SEVERITY_MEDIUM:
		return LevelWarning
	case v1.Severity_SEVERITY_LOW:
		return LevelWarning
	case v1.Severity_SEVERITY_INFO:
		return LevelNote
	default:
		return LevelNone
	}
}

// parseTargets parses the passes sarif location and returns all the valid physical and logical targets in it.
func parseTargets(loc *sarif.Location, lang ExtraContextLanguage) ([]string, error) {
	var (
		targets   = make([]string, 0)
		parseErrs error
	)

	// We can have cases were both locations are defined but, in these cases,
	// the physical location doesn't make much sense, so we just should leverage the logical one.
	if isLogicalLocation(loc) {
		tts, err := parseLogicalTargets(loc, lang)
		if err != nil {
			parseErrs = errors.Join(parseErrs, err)
		}
		targets = append(targets, tts...)
	} else if isPhysicalLocation(loc) {
		tt, err := parsePhysicalTarget(loc)
		if err != nil {
			parseErrs = errors.Join(parseErrs, err)
		}
		targets = append(targets, tt)
	}

	return targets, parseErrs
}

func isPhysicalLocation(loc *sarif.Location) bool {
	return loc.PhysicalLocation != nil
}

// parsePhysicalTarget parses a sarif physical location target.
// We prefix the target with 'file://' so that we know that it's a physical target.
// We add start and end lines information if provided.
// In the case of missing start or end line, we default the undefined one to the same value of the defined one
// because it usually means that the finding affects one line only.
// It can be possible for a target URI to contain a pURL. In that case we simply return that.
func parsePhysicalTarget(loc *sarif.Location) (string, error) {
	if loc.PhysicalLocation == nil {
		return "", nil
	}

	var (
		target    string
		phyLoc    = loc.PhysicalLocation
		targetURI = phyLoc.ArtifactLocation.URI
	)

	if targetURI == nil || *targetURI == "" {
		return "", errors.New("target URI is empty")
	}

	// This means that it's a purl in a physical path.
	if _, err := packageurl.FromString(*targetURI); err == nil {
		return *targetURI, nil
	}

	// Safety check to make sure that we don't end up with malformed targets if
	// the upstream tool is already doing this.
	if !strings.Contains(*targetURI, "file://") {
		target = fmt.Sprintf("file://%s", *targetURI)
	}

	if phyLoc.Region != nil {
		var (
			isStartLineDefined = phyLoc.Region.StartLine != nil
			isEndLineDefined   = phyLoc.Region.EndLine != nil
		)

		switch {
		case isStartLineDefined && isEndLineDefined:
			target = fmt.Sprintf(
				"%s:%d-%d",
				target,
				*phyLoc.Region.StartLine,
				*phyLoc.Region.EndLine,
			)
		case isStartLineDefined && !isEndLineDefined:
			target = fmt.Sprintf(
				"%s:%d-%d",
				target,
				*phyLoc.Region.StartLine,
				*phyLoc.Region.StartLine,
			)
		case !isStartLineDefined && isEndLineDefined:
			target = fmt.Sprintf(
				"%s:%d-%d",
				target,
				*phyLoc.Region.EndLine,
				*phyLoc.Region.EndLine,
			)
		}
	}

	return target, nil
}

func isLogicalLocation(loc *sarif.Location) bool {
	return len(loc.LogicalLocations) > 0
}

// parseLogicalTargets parses all the targets found in the logical locations.
// A logical target must be a valid pURL.
func parseLogicalTargets(loc *sarif.Location, lang ExtraContextLanguage) ([]string, error) {
	var (
		targets  = make([]string, 0)
		parseErr error
	)

	if len(loc.LogicalLocations) == 0 {
		return targets, nil
	}

	for idx, logicLoc := range loc.LogicalLocations {
		if logicLoc == nil {
			parseErr = errors.Join(parseErr, errors.Errorf("logic location is nil at index %d", idx))
			continue
		}

		qualifiedName := *logicLoc.FullyQualifiedName
		// If we have a valid pURL, we are done.
		// Otherwise, we can see if we can leverage the supplied extra context language to see if we can get a valid one.
		if _, err := packageurl.FromString(qualifiedName); err != nil {
			// If we don't have the language, just report an error.
			if lang == "" || lang == ExtraContextLanguageUnspecified {
				parseErr = errors.Join(
					parseErr,
					errors.Errorf(
						"invalid pURL '%s' at index %d: %w",
						qualifiedName,
						idx,
						err,
					),
				)
				continue
			}

			// Otherwise, let's check if we support the language.
			purlNS, ok := extraCtxLangToPURLNS[lang]
			if !ok {
				parseErr = errors.Join(
					parseErr,
					errors.Errorf(
						"invalid pURL '%s' at index %d. The supplied language '%s' is not supported.",
						qualifiedName,
						idx,
						lang,
					),
				)
				continue
			}

			// Now let's put together a potentially valid pURL.
			qualifiedName = fmt.Sprintf("pkg:%s/%s", purlNS, qualifiedName)
			// And check again for its validity.
			if _, err := packageurl.FromString(qualifiedName); err != nil {
				// If invalid, report as an error.
				parseErr = errors.Join(
					parseErr,
					errors.Errorf(
						"invalid pURL '%s' at index %d. Enhanced qualified name '%s' is still not a valid pURL.",
						qualifiedName,
						idx,
						qualifiedName,
					),
				)
				continue
			}
		}

		targets = append(targets, qualifiedName)
	}

	return targets, parseErr
}
