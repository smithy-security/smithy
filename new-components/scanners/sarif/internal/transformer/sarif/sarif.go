package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/package-url/packageurl-go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/smithy/new-components/scanners/sarif/internal/util/ptr"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const (
	TargetTypeRepository TargetType = "repository"
	TargetTypeDependency TargetType = "dependency"
	TargetTypeWeb        TargetType = "web"
	TargetTypeImage      TargetType = "image"
)

type (
	// SmithyIssueCollection represents all the findings in a single Sarif file converted to smithy format.
	SmithyIssueCollection struct {
		ToolName string
		Findings []*ocsf.VulnerabilityFinding
	}

	// TargetType represents the target type.
	TargetType string

	ExtraContextLanguage string

	SarifTransformer struct {
		targetType   TargetType
		clock        clockwork.Clock
		sarifResult  sarif.SchemaJson
		ruleToTools  map[string]sarif.ReportingDescriptor
		taxasByCWEID map[string]sarif.ReportingDescriptor
	}
)

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

		findings, err := parseOut(*run, rules, tool, language)
		if err != nil {
			return nil, errors.Errorf("unexpected parse errors: %w", err)
		}

		if len(findings) == 0 {
			continue
		}

		issueCollection = append(issueCollection, &SmithyIssueCollection{
			ToolName: tool,
			Findings: findings,
		})
	}
	return issueCollection, err
}

func NewSarifTransformer(scanResult *sarif.SchemaJson) (*SarifTransformer, error) {
	if scanResult == nil {
		return nil, errors.Errorf("method 'NewSarifTransformer called with nil scanResult")
	}
	return &SarifTransformer{
		sarifResult:  *scanResult,
		ruleToTools:  make(map[string]sarif.ReportingDescriptor),
		taxasByCWEID: make(map[string]sarif.ReportingDescriptor),
	}, nil
}

func (s *SarifTransformer) ToOCSF(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	slog.Debug(
		"working with",
		slog.Int("num_sarif_runs", len(s.sarifResult.Runs)),
		slog.Int("num_sarif_results", func(runs []sarif.Run) int {
			var countRes = 0
			for _, run := range runs {
				countRes += len(run.Results)
			}
			return countRes
		}(s.sarifResult.Runs)),
	)

	// preparation
	var (
		vulns = make([]*ocsf.VulnerabilityFinding, 0)
	)

	// Preparing helper data sets to reconstruct linked data.
	for _, run := range s.sarifResult.Runs {
		for _, res := range run.Results {
			s.ruleToTools[*res.RuleId] = sarif.ReportingDescriptor{}
		}
		for _, res := range run.Tool.Driver.Rules {
			if _, ok := s.ruleToTools[res.Id]; ok {
				s.ruleToTools[res.Id] = res
			}
		}
		for _, taxonomy := range run.Taxonomies {
			for _, taxa := range taxonomy.Taxa {
				s.taxasByCWEID[taxa.Id] = taxa
			}
		}
	}
	var (
		findings = make([]*ocsf.VulnerabilityFinding, 0)
		parseErr error
	)
	for _, run := range s.sarifResult.Runs {
		for _, res := range run.Results {
			finding, err := s.transformFinding("", &res)
			if err != nil {
				errors.Join(parseErr, err)
			}
			vulns = append(vulns, finding)

		}
	}
	return findings, parseErr
}

// func (s *SarifTransformer) FromOCSF(ctx context.Context) (*sarif.SchemaJson, error){
// 	// TODO
// }

func (s *SarifTransformer) transformToOCSF(toolName string, res *sarif.Result) (*ocsf.VulnerabilityFinding, error) {
	// TODO:
	// * AnalysisTarget?
	// * Attachments
	// * Result.BaselineState actually says if the finding is new, we should take it into account
	// * CodeFlows contains reachability tracing sometimes
	// * Fixes is useful when we can understand and generate fix results
	// * GraphTraversals <<-- how different from codeflows?
	// * Graphs???
	// * PartialFingerprints??
	// * RelatedLocations
	// * Stacks
	// * Suppressions
	// * WebRequest
	// * WebResponse
	// * WorkItemUris
	affectedCode, affectedPackages := s.mapAffected(res)

	// Location
	fixAvailable := false
	if len(res.Fixes) > 0 {
		fixAvailable = true
	}
	var (
		ruleID, ruleGuid *string
		severityID             = s.mapSeverity(res.Level)
		title, desc            = s.mapTitleDesc(res, s.ruleToTools)
		occurrencesCount int32 = 0
	)
	dataSource, err := s.mapDataSource(res.Locations)
	if err != nil {
		return nil, errors.Errorf("failed to map data source: %w", err)
	}
	confidence := s.mapConfidence(*ruleID, s.ruleToTools)
	if res.RuleId != nil {
		ruleID = res.RuleId
	} else if res.Rule != nil {
		if res.Rule.ToolComponent != nil && res.Rule.ToolComponent.Name != nil {
			ruleID = res.Rule.ToolComponent.Name
		}
		if res.Rule.Guid != nil {
			ruleGuid = res.Rule.Guid
		}
	}
	if res.OccurrenceCount != nil {
		occurrencesCount = int32(*res.OccurrenceCount)
	}
	labels, err := s.mapProperties(res.Properties)
	if err != nil {
		return nil, err
	}
	var firstSeenTime, lastSeenTime time.Time
	if res.Provenance != nil {
		firstSeenTime = *res.Provenance.FirstDetectionTimeUtc
		lastSeenTime = *res.Provenance.LastDetectionTimeUtc
	}
	return &ocsf.VulnerabilityFinding{
		// Actor
		// Api
		ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
		ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
		CategoryName: ptr.Ptr(ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS.String()),
		CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
		ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
		ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),
		Confidence:   ptr.Ptr(confidence.String()),
		ConfidenceId: ptr.Ptr(confidence),
		Count:        ptr.Ptr(occurrencesCount),
		// Cloud
		// Comment
		// ConfidenceScore
		// Device
		// Duration
		// EndTime
		// EndTimeDt
		FindingInfo: &ocsf.FindingInfo{
			//	Analytic
			// Attacks
			CreatedTime:   ptr.Ptr(s.clock.Now().Unix()),
			CreatedTimeDt: timestamppb.New(s.clock.Now()),
			DataSources: []string{
				dataSource,
			},
			Desc:            &desc,
			FirstSeenTime:   ptr.Ptr(firstSeenTime.Unix()),
			FirstSeenTimeDt: timestamppb.New(firstSeenTime),
			// KillChain
			LastSeenTime:   ptr.Ptr(lastSeenTime.Unix()),
			LastSeenTimeDt: timestamppb.New(lastSeenTime),
			// ModifiedTime
			// ModifiedTimeDt
			// ProductUid
			// RelatedAnalytics
			// RelatedEvents
			SrcUrl: res.HostedViewerUri,
			Title:  title,
			// Types:
			Uid: *res.Guid,
		},
		Message: res.Message.Text,
		Metadata: &ocsf.Metadata{

			CorrelationUid: res.CorrelationGuid,
			// DataClassification
			EventCode: ruleID,
			// Extension
			// Extensions
			Labels: labels,
			// LogLevel
			// LogName
			// LogProvider
			// LogVersion
			// LoggedTime
			// LoggedTimeDt
			// Loggers
			// ModifiedTime
			// ModifiedTimeDt
			// OriginalTime
			// ProcessedTime
			// ProcessedTimeDt
			Product: &ocsf.Product{
				Name: &toolName,
			},
			// Profiles
			// Sequence
			// TenantUid
			Uid: ruleGuid,
			// Version
		},

		Severity:   ptr.Ptr(severityID.String()),
		SeverityId: severityID,
		// StartTime
		// StartTimeDt
		Status:   ptr.Ptr(s.mapResultKind(res.Kind).String()),
		StatusId: ptr.Ptr(s.mapResultKind(res.Kind)),
		// StatusDetail
		// Time
		// TimeDt
		// TimezoneOffset
		// TypeName
		// TypeUid
		// Unmapped
		Vulnerabilities: []*ocsf.Vulnerability{
			{

				AffectedCode:     affectedCode,
				AffectedPackages: affectedPackages,
				// TODO: regexp CVE extraction?

				// Cve:              ,
				Cwe:             s.mapCWE(*ruleID),
				Desc:            &desc,
				FirstSeenTime:   ptr.Ptr(firstSeenTime.Unix()),
				FirstSeenTimeDt: timestamppb.New(firstSeenTime),
				FixAvailable:    ptr.Ptr(fixAvailable),
				// IsExploitAvailable: ,
				IsFixAvailable: ptr.Ptr(fixAvailable),

				// KbArticleList
				// KbArticles
				LastSeenTime:   ptr.Ptr(lastSeenTime.Unix()),
				LastSeenTimeDt: timestamppb.New(lastSeenTime),
				// Packages
				// References
				// RelatedVulnerabilities
				// Remediation
				Severity:   ptr.Ptr(severityID.String()),
				Title:      ptr.Ptr(title),
				VendorName: &toolName,
			},
		},
	}, nil
}

func (s *SarifTransformer) mapProperties(props *sarif.PropertyBag) ([]string, error) {
	if props == nil {
		return nil, nil
	}
	res := props.Tags
	if props.AdditionalProperties != nil {
		extra, err := json.Marshal(props.AdditionalProperties)
		if err != nil {
			return nil, err
		}

		res = append(res, string(extra))
	}
	return res, nil
}

func (s *SarifTransformer) mapResultKind(kind sarif.ResultKind) ocsf.VulnerabilityFinding_StatusId {
	switch kind {
	case sarif.ResultKindNotApplicable:
		return ocsf.VulnerabilityFinding_STATUS_ID_SUPPRESSED // false positive or duplicate or user does not want to see for some reason
	case sarif.ResultKindFail: // open finding, we need to work with it
	case sarif.ResultKindOpen:
		return ocsf.VulnerabilityFinding_STATUS_ID_NEW
	case sarif.ResultKindPass: // scan has passed, this finding need not exist
		return ocsf.VulnerabilityFinding_STATUS_ID_RESOLVED
	case sarif.ResultKindInformational: // finding is info or under review already, someone is taking care of it or it doesn't need attention
	case sarif.ResultKindReview:
		return ocsf.VulnerabilityFinding_STATUS_ID_IN_PROGRESS
	}
	return ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN
}

func (s *SarifTransformer) mapAffectedPacakge(fixes []sarif.Fix, location *sarif.Location, purl packageurl.PackageURL) *ocsf.AffectedPackage {

	affectedPackage := &ocsf.AffectedPackage{
		Purl:           ptr.Ptr(purl.String()),
		Name:           purl.Name,
		PackageManager: &purl.Type,
	}
	for _, fix := range fixes {
		for _, change := range fix.ArtifactChanges {
			if change.ArtifactLocation.Uri != nil && *change.ArtifactLocation.Uri == purl.String() {
				affectedPackage.Remediation = &ocsf.Remediation{
					Desc: *fix.Description.Text,
				}
			}
		}
	}
	return affectedPackage
}

// TODO: still need to find a way to detect snyk that doesn't speak purl and trivy that speaks docker
//
//	or maybe snyk and trivy get their own sarif flavor?
func (s *SarifTransformer) mapAffected(res *sarif.Result) ([]*ocsf.AffectedCode, []*ocsf.AffectedPackage) {
	var affectedCode = make([]*ocsf.AffectedCode, 0)
	var affectedPackages = make([]*ocsf.AffectedPackage, 0)
	for _, location := range res.Locations {
		if location.PhysicalLocation == nil {
			continue
		}
		var (
			ac = &ocsf.AffectedCode{
				File: &ocsf.File{},
			}
			physicalLocation = location.PhysicalLocation
		)
		if physicalLocation.ArtifactLocation != nil && physicalLocation.ArtifactLocation.Uri != nil {
			if p, e := packageurl.FromString(*physicalLocation.ArtifactLocation.Uri); e == nil {
				affectedPackages = append(affectedPackages, s.mapAffectedPacakge(res.Fixes, &location, p))
			} else {
				ac.File.Name = *location.PhysicalLocation.ArtifactLocation.Uri
				ac.File.Path = ptr.Ptr(fmt.Sprintf("file://%s", *location.PhysicalLocation.ArtifactLocation.Uri))
			}
		}

		if physicalLocation.Region != nil {
			ac.StartLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.StartLine))
			ac.EndLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.EndLine))
		}

		if ac != (&ocsf.AffectedCode{}) {
			affectedCode = append(affectedCode, ac)
		}
	}

	return affectedCode, affectedPackages
}

func (s *SarifTransformer) mapSeverity(sarifResLevel sarif.ResultLevel) ocsf.VulnerabilityFinding_SeverityId {
	severity, ok := map[string]ocsf.VulnerabilityFinding_SeverityId{
		"warning": ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
		"error":   ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
		"note":    ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
		"none":    ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN,
	}[string(sarifResLevel)]
	if !ok {
		return ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN
	}
	return severity
}

func (s *SarifTransformer) mapConfidence(ruleID string, ruleToTools map[string]sarif.ReportingDescriptor) (confidence ocsf.VulnerabilityFinding_ConfidenceId) {
	confidence = ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN

	toolRule, ok := ruleToTools[ruleID]
	if !ok || toolRule.Properties == nil {
		return
	}

	props, ok := toolRule.Properties.AdditionalProperties.(map[string]any)
	if !ok {
		return
	}

	rawConfidence, ok := props["precision"]
	if !ok {
		return
	}

	rawConfidenceStr, ok := rawConfidence.(string)
	if !ok {
		return
	}

	switch rawConfidenceStr {
	case "high":
		return ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH
	case "medium":
		return ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM
	case "low":
		return ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW
	}

	return
}

func (s *SarifTransformer) mapTitleDesc(res *sarif.Result, ruleToTools map[string]sarif.ReportingDescriptor) (title string, descr string) {
	title, descr = *res.Message.Text, *res.Message.Text

	rule, ok := ruleToTools[*res.RuleId]
	if !ok {
		return
	}

	if rule.Name != nil && *rule.Name != "" {
		title = *rule.Name
	}

	if rule.FullDescription != nil && rule.FullDescription.Text != "" {
		descr = rule.FullDescription.Text
	}

	return
}

func (s *SarifTransformer) mapCWE(ruleID string) *ocsf.Cwe {
	cwe := &ocsf.Cwe{}

	rule, ok := s.ruleToTools[ruleID]
	if !ok {
		return nil
	}

	for _, rel := range rule.Relationships {
		cwe.Uid = *rel.Target.Id
		taxa, ok := s.taxasByCWEID[cwe.Uid]
		if !ok {
			continue
		}
		cwe.SrcUrl = taxa.HelpUri
		if taxa.FullDescription != nil && taxa.FullDescription.Text != "" {
			cwe.Caption = ptr.Ptr(taxa.FullDescription.Text)
		}
	}

	return cwe
}

func (s *SarifTransformer) mapDataSource(locations []sarif.Location) (string, error) {
	for _, location := range locations {
		if location.PhysicalLocation == nil ||
			location.PhysicalLocation.ArtifactLocation == nil ||
			location.PhysicalLocation.ArtifactLocation.Uri == nil {
			continue
		}

		// TODO sort out targettypes -- add repo, deps, website, oci_image
		targetType, ok := map[TargetType]ocsffindinginfo.DataSource_TargetType{
			TargetTypeRepository: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		}[s.targetType]
		if !ok {
			targetType = ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED
		}

		dataSource := ocsffindinginfo.DataSource{
			TargetType: targetType,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      *location.PhysicalLocation.ArtifactLocation.Uri,
			},
		}

		if location.PhysicalLocation.Region != nil {
			dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   uint32(*location.PhysicalLocation.Region.StartLine),
					EndLine:     uint32(*location.PhysicalLocation.Region.EndLine),
					StartColumn: uint32(*location.PhysicalLocation.Region.StartColumn),
					EndColumn:   uint32(*location.PhysicalLocation.Region.EndColumn),
				},
			}
		}

		b, err := protojson.Marshal(&dataSource)
		if err != nil {
			return "", errors.Errorf("failed to marshal data source to JSON, %v", err)
		}

		return string(b), nil
	}

	return "", errors.New("missing location information in finding")
}
