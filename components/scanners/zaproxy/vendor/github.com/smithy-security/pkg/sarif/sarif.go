package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-errors/errors"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/package-url/packageurl-go"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/pkg/sarif/internal/ptr"
	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
)

type (
	SarifTransformer struct {
		findingsEcosystem string
		clock             clockwork.Clock
		uUIDProvider      UUIDProvider
		sarifResult       sarif.SchemaJson
		cveRegExp         *regexp.Regexp
		ruleToTools       map[string]sarif.ReportingDescriptor
		taxasByCWEID      map[string]sarif.ReportingDescriptor
		ruleToEcosystem   map[string]string
	}
	UUIDProvider interface {
		String() string
	}

	RealUUIDProvider struct {
	}
)

var typeName = map[int64]string{
	200200: "Unknown",
	200201: "Create",
	200202: "Update",
	200203: "Close",
	200299: "Other",
}

func (r RealUUIDProvider) String() string {
	return uuid.NewString()
}

func NewTransformer(scanResult *sarif.SchemaJson,
	findingsEcosystem string,
	clock clockwork.Clock,
	idProvider UUIDProvider) (*SarifTransformer, error) {
	if scanResult == nil {
		return nil, errors.Errorf("method 'NewTransformer called with nil scanResult")
	}
	if clock == nil {
		clock = clockwork.NewRealClock()
	}
	if idProvider == nil {
		idProvider = RealUUIDProvider{}
	}

	return &SarifTransformer{
		clock:             clock,
		sarifResult:       *scanResult,
		findingsEcosystem: findingsEcosystem,
		uUIDProvider:      idProvider,
		ruleToTools:       make(map[string]sarif.ReportingDescriptor),
		taxasByCWEID:      make(map[string]sarif.ReportingDescriptor),
		cveRegExp:         regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9-])(CVE-\d{4}-\d{4,7})(?:[^A-Za-z0-9-]|$)`),
	}, nil
}

func (s *SarifTransformer) ToOCSF(ctx context.Context, datasource *ocsffindinginfo.DataSource) ([]*ocsf.VulnerabilityFinding, error) {
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

	vulns := make([]*ocsf.VulnerabilityFinding, 0)
	var parseErr error
	s.ruleToEcosystem = s.rulesToEcosystem()
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

	for _, run := range s.sarifResult.Runs {
		toolName := run.Tool.Driver.Name
		for _, res := range run.Results {
			finding, err := s.transformToOCSF(toolName, &res, datasource)
			if err != nil {
				errors.Join(parseErr, err)
			}
			vulns = append(vulns, finding)
		}
	}
	return vulns, parseErr
}

func (s *SarifTransformer) transformToOCSF(toolName string, res *sarif.Result, datasource *ocsffindinginfo.DataSource) (*ocsf.VulnerabilityFinding, error) {
	slog.Debug("parsing run from", slog.String("toolname", toolName))
	affectedCode, affectedPackages := s.mapAffected(res, datasource)

	var (
		ruleID, ruleGuid *string
		severityID       = s.mapSeverity(res.Level)
		title, desc      = s.mapTitleDesc(res, s.ruleToTools)
		occurrencesCount *int32
		now              = s.clock.Now()
	)
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
	confidence := s.mapConfidence(*ruleID, s.ruleToTools)

	if res.OccurrenceCount != nil {
		occurrencesCount = ptr.Ptr(int32(*res.OccurrenceCount))
	} else {
		occurrencesCount = ptr.Ptr(int32(1))
	}
	labels, err := s.mapProperties(res.Properties)
	if err != nil {
		return nil, err
	}
	var firstSeenTimeDT, lastSeenTimeDT, modifiedTimeDT *timestamppb.Timestamp
	var firstSeenTime, lastSeenTime, modifiedTime *int64
	if res.Provenance != nil {
		if res.Provenance.FirstDetectionTimeUtc != nil {
			firstSeenTimeDT = timestamppb.New(*res.Provenance.FirstDetectionTimeUtc)
			firstSeenTime = ptr.Ptr(res.Provenance.FirstDetectionTimeUtc.Unix())
		} else {
			firstSeenTime = ptr.Ptr(now.Unix())
			firstSeenTimeDT = timestamppb.New(now)
		}

		if res.Provenance.LastDetectionTimeUtc != nil {
			lastSeenTimeDT = timestamppb.New(*res.Provenance.LastDetectionTimeUtc)
			lastSeenTime = ptr.Ptr(res.Provenance.LastDetectionTimeUtc.Unix())
		} else {
			lastSeenTime = ptr.Ptr(now.Unix())
			lastSeenTimeDT = timestamppb.New(now)
		}

		modifiedTime = ptr.Ptr(now.Unix())
		modifiedTimeDT = timestamppb.New(now)
	} else {
		firstSeenTime = ptr.Ptr(now.Unix())
		firstSeenTimeDT = timestamppb.New(now)
		lastSeenTime = ptr.Ptr(now.Unix())
		lastSeenTimeDT = timestamppb.New(now)
		modifiedTime = ptr.Ptr(now.Unix())
		modifiedTimeDT = timestamppb.New(now)
	}

	rule := s.ruleToTools[*ruleID]
	var cve *ocsf.Cve
	if rule.FullDescription != nil {
		if strings.HasPrefix(*ruleID, "CVE-") {
			cve = &ocsf.Cve{}
			cve.Uid = *ruleID
			cve.Desc = &rule.FullDescription.Text
		} else if uid := s.extractCVE(rule.FullDescription.Text); uid != "" {
			cve = &ocsf.Cve{}
			cve.Uid = uid
			cve.Desc = &rule.FullDescription.Text
		}
	}
	findingUid := ""
	if res.Guid != nil {
		findingUid = *res.Guid
	} else {
		findingUid = s.uUIDProvider.String()
	}

	// Location
	var fixAvailable = ptr.Ptr(len(res.Fixes) > 0)

	if err := s.mergeDatasources(res, datasource); err != nil {
		return nil, err
	}
	ds, err := protojson.Marshal(datasource)
	if err != nil {
		return nil, err
	}
	activityID := ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE
	classID := ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING
	return &ocsf.VulnerabilityFinding{
		ActivityId:   activityID,
		ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
		CategoryName: ptr.Ptr(ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS.String()),
		CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
		ClassUid:     classID,
		ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),
		Confidence:   ptr.Ptr(confidence.String()),
		ConfidenceId: ptr.Ptr(confidence),
		Count:        occurrencesCount,
		FindingInfo: &ocsf.FindingInfo{
			CreatedTime:     ptr.Ptr(now.Unix()),
			CreatedTimeDt:   timestamppb.New(now),
			DataSources:     []string{string(ds)},
			Desc:            &desc,
			FirstSeenTime:   firstSeenTime,
			FirstSeenTimeDt: firstSeenTimeDT,
			LastSeenTime:    lastSeenTime,
			LastSeenTimeDt:  lastSeenTimeDT,
			ModifiedTime:    modifiedTime,
			ModifiedTimeDt:  modifiedTimeDT,
			SrcUrl:          res.HostedViewerUri,
			Title:           title,
			Uid:             findingUid,
			ProductUid:      &toolName,
		},
		Message: res.Message.Text,
		Metadata: &ocsf.Metadata{
			CorrelationUid: res.CorrelationGuid,
			EventCode:      ruleID,
			Labels:         labels,
			Product: &ocsf.Product{
				Name: &toolName,
			},
			Uid: ruleGuid,
		},

		Severity:   ptr.Ptr(severityID.String()),
		SeverityId: severityID,
		StartTime:  ptr.Ptr(now.Unix()),
		Status:     ptr.Ptr(s.mapResultKind(res.Kind).String()),
		StatusId:   ptr.Ptr(s.mapResultKind(res.Kind)),
		Time:       now.Unix(),
		TimeDt:     timestamppb.New(now),
		TypeName:   ptr.Ptr(typeName[int64(classID)*100+int64(activityID)]),
		TypeUid:    int64(classID)*100 + int64(activityID),
		Vulnerabilities: []*ocsf.Vulnerability{
			{
				AffectedCode:     affectedCode,
				AffectedPackages: affectedPackages,
				Cve:              cve,
				Cwe:              s.mapCWE(*ruleID),
				Desc:             &desc,
				FirstSeenTime:    firstSeenTime,
				FirstSeenTimeDt:  firstSeenTimeDT,
				FixAvailable:     fixAvailable,
				IsFixAvailable:   fixAvailable,
				LastSeenTime:     lastSeenTime,
				LastSeenTimeDt:   lastSeenTimeDT,
				Severity:         ptr.Ptr(severityID.String()),
				Title:            ptr.Ptr(title),
				VendorName:       &toolName,
			},
		},
	}, nil
}

func (s *SarifTransformer) mapProperties(props *sarif.PropertyBag) ([]string, error) {
	if props == nil {
		return nil, nil
	}
	res := props.Tags
	if props.AdditionalProperties == nil {
		return res, nil
	}
	extra, err := json.Marshal(props.AdditionalProperties)
	if err != nil {
		return nil, err
	}

	res = append(res, string(extra))
	return res, nil
}

func (s *SarifTransformer) mapResultKind(kind sarif.ResultKind) ocsf.VulnerabilityFinding_StatusId {
	switch kind {
	case sarif.ResultKindNotApplicable:
		return ocsf.VulnerabilityFinding_STATUS_ID_SUPPRESSED // false positive or duplicate or user does not want to see for some reason
	case sarif.ResultKindFail: // scan has failed findings usually used for some sort of release gating, that's an open finding for all intents and purposes
	case sarif.ResultKindOpen: // open finding, we need to work with it
		return ocsf.VulnerabilityFinding_STATUS_ID_NEW
	case sarif.ResultKindPass: // scan has passed, this finding need not exist
		return ocsf.VulnerabilityFinding_STATUS_ID_RESOLVED
	case sarif.ResultKindInformational: // finding is info or under review already, someone is taking care of it or it doesn't need attention
	case sarif.ResultKindReview:
		return ocsf.VulnerabilityFinding_STATUS_ID_IN_PROGRESS
	}
	// by default, a scanner that doesn't know what status the finding has should always think the status is new unless enrichment says otherwise
	return ocsf.VulnerabilityFinding_STATUS_ID_NEW
}

func (s *SarifTransformer) extractCVE(text string) string {
	match := s.cveRegExp.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func (s *SarifTransformer) isSnykURI(uri string) bool {
	return strings.HasPrefix(uri, "https_//")
}

func (s *SarifTransformer) mapAffectedPackage(fixes []sarif.Fix, purl packageurl.PackageURL) *ocsf.AffectedPackage {
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

func (s *SarifTransformer) detectPackageFromPhysicalLocation(physicalLocation sarif.PhysicalLocation, ecosyststem string, datasource *ocsffindinginfo.DataSource) *packageurl.PackageURL {
	if s.isSnykURI(*physicalLocation.ArtifactLocation.Uri) {
		return nil
	}
	if p, e := packageurl.FromString(*physicalLocation.ArtifactLocation.Uri); e == nil {
		return &p
	}
	// if we get hinted that this scan is for dependencies and the deps have a specific ecosystem we can assume more things
	if s.findingsEcosystem != "" || ecosyststem != "" {
		pkgManager := s.findingsEcosystem
		if ecosyststem != "" {
			pkgManager = ecosyststem
		}
		switch datasource.TargetType {
		case ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY:
			purl := fmt.Sprintf("pkg:%s/%s", pkgManager, *physicalLocation.ArtifactLocation.Uri)
			if p, e := packageurl.FromString(purl); e == nil {
				return &p
			}
		case ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE:
			purl := datasource.OciPackageMetadata.PackageUrl
			if p, e := packageurl.FromString(purl); e == nil {
				return &p
			}
		}
	}
	return nil
}

// this method is to get around Snyk's weird Sarif parsing
func (s *SarifTransformer) detectPackageFromLogicalLocation(logicalLocation sarif.LogicalLocation, pkgType string, datasource *ocsffindinginfo.DataSource) *packageurl.PackageURL {
	if p, e := packageurl.FromString(*logicalLocation.FullyQualifiedName); e == nil {
		return &p
	}
	// if we get hinted that this scan is for dependencies and the deps have a specific ecosystem we can assume more things
	if datasource.TargetType == ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY && (s.findingsEcosystem != "" || pkgType != "") {
		// snyk puts parts of the purl in logical locations
		pkgNamespace := s.findingsEcosystem
		if pkgType != "" {
			pkgNamespace = pkgType
		}
		purl := fmt.Sprintf("pkg:%s/%s", pkgNamespace, *logicalLocation.FullyQualifiedName)
		if p, e := packageurl.FromString(purl); e == nil {
			return &p
		}
	}
	return nil
}

func (s *SarifTransformer) rulesToEcosystem() map[string]string {
	result := map[string]string{}
	for _, run := range s.sarifResult.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.Properties != nil {
				for _, tag := range rule.Properties.Tags {
					if _, ok := packageurl.KnownTypes[tag]; ok {
						result[rule.Id] = tag
					}
				}
			}
		}
	}
	return result
}

func (s *SarifTransformer) mapAffected(res *sarif.Result, datasource *ocsffindinginfo.DataSource) ([]*ocsf.AffectedCode, []*ocsf.AffectedPackage) {
	var affectedCode []*ocsf.AffectedCode
	var affectedPackages []*ocsf.AffectedPackage
	if datasource.TargetType == ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE { // websites do not carry code or package info
		return nil, nil
	}
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
		pkgType := s.findingsEcosystem
		ruleID := ""
		if res.RuleId != nil {
			ruleID = *res.RuleId
		} else if res.Rule != nil && res.Rule.Id != nil {
			ruleID = *res.Rule.Id
		}
		if eco, ok := s.ruleToEcosystem[ruleID]; ok {
			pkgType = eco
		}
		if physicalLocation.ArtifactLocation != nil && physicalLocation.ArtifactLocation.Uri != nil {
			if p := s.detectPackageFromPhysicalLocation(*physicalLocation, pkgType, datasource); p != nil {
				affectedPackages = append(affectedPackages, s.mapAffectedPackage(res.Fixes, *p))
			} else if !s.isSnykURI(*location.PhysicalLocation.ArtifactLocation.Uri) {
				// Snyk special case, they use the repo url with some weird replacement as the artifact location
				ac.File.Name = *location.PhysicalLocation.ArtifactLocation.Uri
				ac.File.Path = ptr.Ptr(fmt.Sprintf("file://%s", *location.PhysicalLocation.ArtifactLocation.Uri))
			}
		}
		if physicalLocation.Region != nil {
			if location.PhysicalLocation.Region.StartLine != nil {
				ac.StartLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.StartLine))
			}
			if location.PhysicalLocation.Region.EndLine != nil {
				ac.EndLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.EndLine))
			}
		}
		if ac != (&ocsf.AffectedCode{}) {
			affectedCode = append(affectedCode, ac)
		}
		for _, logicalLocation := range location.LogicalLocations {
			if p := s.detectPackageFromLogicalLocation(logicalLocation, pkgType, datasource); p != nil {
				affectedPackages = append(affectedPackages, s.mapAffectedPackage(res.Fixes, *p))
			}
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
	if cwe.Uid != "" {
		return cwe
	}
	// if all else fails try to match regexp with tags (semgrep, snyk and codeql do that)
	if rule.Properties != nil {
		for _, tag := range rule.Properties.Tags {
			re := regexp.MustCompile(`(?i)CWE-\d{3,}`)
			matches := re.FindAllString(tag, -1)
			for _, match := range matches {
				if match != "" {
					cwe.Uid = strings.ReplaceAll(strings.ToLower(match), "cwe-", "")
					return cwe // we only care about 1, since ocsf only supports one cwe
				}
			}

		}
	}
	return nil // all failed, no cwe
}

func (s *SarifTransformer) mergeDatasources(res *sarif.Result, datasource *ocsffindinginfo.DataSource) error {

	for _, location := range res.Locations {
		if location.PhysicalLocation == nil ||
			location.PhysicalLocation.ArtifactLocation == nil ||
			location.PhysicalLocation.ArtifactLocation.Uri == nil {
			continue
		}

		var dataSourceURI string
		if _, err := filepath.Abs(*location.PhysicalLocation.ArtifactLocation.Uri); err == nil {
			dataSourceURI = "file://" + *location.PhysicalLocation.ArtifactLocation.Uri
		}

		switch datasource.TargetType {
		case ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE:
			purl, err := packageurl.FromString("pkg:" + s.findingsEcosystem + "/" + *location.PhysicalLocation.ArtifactLocation.Uri)
			if err != nil {
				return errors.Errorf("failed to parse package url:'%s', %v", *location.PhysicalLocation.ArtifactLocation.Uri, err)
			}
			datasource.Uri = &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_PURL,
				Path:      purl.String(),
			}
		case ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY:
			datasource.Uri = &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      dataSourceURI,
			}
		case ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE:
			datasource.Uri = &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
				Path:      *location.PhysicalLocation.ArtifactLocation.Uri,
			}
		}

		// snyk special handling, snyk sets the repo as artifact location instead of the dependencies file
		//  this is invalid in our case
		if s.isSnykURI(*location.PhysicalLocation.ArtifactLocation.Uri) {
			datasource.Uri = nil
		}

		if location.PhysicalLocation.Region != nil {
			startLine := 0
			endLine := 0
			startColumn := 0
			endColumn := 0
			if location.PhysicalLocation.Region.StartLine != nil {
				startLine = *location.PhysicalLocation.Region.StartLine
			}
			if location.PhysicalLocation.Region.EndLine != nil {
				endLine = *location.PhysicalLocation.Region.EndLine
			}
			if location.PhysicalLocation.Region.StartColumn != nil {
				startColumn = *location.PhysicalLocation.Region.StartColumn
			}
			if location.PhysicalLocation.Region.EndColumn != nil {
				endColumn = *location.PhysicalLocation.Region.EndColumn
			}
			datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   uint32(startLine),
					EndLine:     uint32(endLine),
					StartColumn: uint32(startColumn),
					EndColumn:   uint32(endColumn),
				},
			}
		}
		return nil
	}
	return errors.New("missing location information in finding")
}
