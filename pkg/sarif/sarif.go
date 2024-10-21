package sarif

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
)

// SmithyIssueCollection represents all the findings in a single Sarif file converted to smithy format.
type SmithyIssueCollection struct {
	ToolName string
	Issues   []*v1.Issue
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
func ToSmithy(inFile string) ([]*SmithyIssueCollection, error) {
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
		issueCollection = append(issueCollection, &SmithyIssueCollection{
			ToolName: tool,
			Issues:   parseOut(*run, rules, tool),
		})
	}
	return issueCollection, err
}

func parseOut(run sarif.Run, rules map[string]*sarif.ReportingDescriptor, toolName string) []*v1.Issue {
	issues := []*v1.Issue{}
	for _, res := range run.Results {
		for _, loc := range res.Locations {
			target, uri, sl, el := "", "", "", ""
			if loc.PhysicalLocation == nil {
				for _, ll := range loc.LogicalLocations {
					// do the same for logical locs
					target = *ll.FullyQualifiedName
					issues = addIssue(rules, issues, target, toolName, res)
				}
			} else {
				if loc.PhysicalLocation.ArtifactLocation.URI != nil {
					uri = *loc.PhysicalLocation.ArtifactLocation.URI
				}
				if loc.PhysicalLocation.Region != nil {
					if loc.PhysicalLocation.Region.StartLine != nil {
						sl = fmt.Sprintf("%d", *loc.PhysicalLocation.Region.StartLine)
					}
					if loc.PhysicalLocation.Region.EndLine != nil {
						el = fmt.Sprintf("%d", *loc.PhysicalLocation.Region.EndLine)
					} else {
						el = sl
					}
					target = fmt.Sprintf("%s:%s-%s", uri, sl, el)
				} else {
					target = uri
				}
				issues = addIssue(rules, issues, target, toolName, res)
			}

		}
	}
	return issues
}

func addIssue(rules map[string]*sarif.ReportingDescriptor, issues []*v1.Issue, target, toolName string, res *sarif.Result) []*v1.Issue {
	rule, ok := rules[*res.RuleID]
	var description string
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
		Severity:    levelToseverity(*res.Level),
		Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
	})

	return issues
}

// levelToseverity transforms error, warning and note levels to high, medium and low respectively.
func levelToseverity(level string) v1.Severity {
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
