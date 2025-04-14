package transformer

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/new-components/scanners/gosec/internal/util/ptr"
)

const TargetTypeRepository TargetType = "repository"

type (
	// GosecTransformerOption allows customising the transformer.
	GosecTransformerOption func(g *gosecTransformer) error

	// TargetType represents the target type.
	TargetType string

	gosecTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// GosecTransformerWithClock allows customising the underlying clock.
func GosecTransformerWithClock(clock clockwork.Clock) GosecTransformerOption {
	return func(g *gosecTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// GosecTransformerWithTarget allows customising the underlying target type.
func GosecTransformerWithTarget(target TargetType) GosecTransformerOption {
	return func(g *gosecTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// GosecRawOutFilePath allows customising the underlying raw out file path.
func GosecRawOutFilePath(path string) GosecTransformerOption {
	return func(g *gosecTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new gosec transformer.
func New(opts ...GosecTransformerOption) (*gosecTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"GOSEC_RAW_OUT_FILE_PATH",
		"gosec.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"GOSEC_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := gosecTransformer{
		rawOutFilePath: rawOutFilePath,
		targetType:     TargetType(target),
		clock:          clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	switch {
	case t.rawOutFilePath == "":
		return nil, errors.New("invalid empty raw output file")
	case t.targetType == "":
		return nil, errors.New("invalid empty target type")
	}

	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *gosecTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw gosec output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw gosec output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw gosec output!",
		slog.Int("num_sarif_runs", len(report.Runs)),
		slog.Int("num_sarif_results", func(runs []sarifschemav210.Run) int {
			var countRes = 0
			for _, run := range runs {
				countRes += len(run.Results)
			}
			return countRes
		}(report.Runs)),
	)

	var (
		now          = g.clock.Now().Unix()
		vulns        = make([]*ocsf.VulnerabilityFinding, 0)
		ruleToTools  = make(map[string]sarifschemav210.ReportingDescriptor)
		taxasByCWEID = make(map[string]sarifschemav210.ReportingDescriptor)
	)

	logger.Debug("preparing to parse raw sarif findings to ocsf vulnerability findings...")

	// Preparing helper data sets to reconstruct linked data.
	for _, run := range report.Runs {
		for _, res := range run.Results {
			ruleToTools[*res.RuleId] = sarifschemav210.ReportingDescriptor{}
		}
		for _, res := range run.Tool.Driver.Rules {
			if _, ok := ruleToTools[res.Id]; ok {
				ruleToTools[res.Id] = res
			}
		}
		for _, taxonomy := range run.Taxonomies {
			for _, taxa := range taxonomy.Taxa {
				taxasByCWEID[taxa.Id] = taxa
			}
		}
	}

	for _, run := range report.Runs {
		var runVulns = make([]*ocsf.VulnerabilityFinding, 0, len(run.Results))
		for _, res := range run.Results {
			var (
				ruleID                 = *res.RuleId
				confidence             = g.mapConfidence(ruleID, ruleToTools)
				severityID             = g.mapSeverity(res.Level)
				title, desc            = g.mapTitleDesc(res, ruleToTools)
				occurrencesCount int32 = 0
			)

			dataSource, err := g.mapDataSource(ctx, res.Locations)
			if err != nil {
				return nil, errors.Errorf("failed to map data source: %w", err)
			}

			if res.OccurrenceCount != nil {
				occurrencesCount = int32(*res.OccurrenceCount)
			}

			vulns = append(
				vulns,
				&ocsf.VulnerabilityFinding{
					ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
					ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
					CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
					ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
					ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),
					Confidence:   ptr.Ptr(confidence.String()),
					ConfidenceId: ptr.Ptr(confidence),
					Count:        ptr.Ptr(occurrencesCount),
					FindingInfo: &ocsf.FindingInfo{
						CreatedTime: &now,
						DataSources: []string{
							dataSource,
						},
						Desc:          ptr.Ptr(desc),
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						ModifiedTime:  &now,
						ProductUid:    ptr.Ptr(run.Tool.Driver.Name),
						Title:         title,
						Uid:           ruleID,
					},
					Message:    res.Message.Text,
					Severity:   ptr.Ptr(severityID.String()),
					SeverityId: severityID,
					StartTime:  &now,
					Status:     ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW.String()),
					StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
					Time:       now,
					TypeUid: int64(
						ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
							100 +
							ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
					),
					Vulnerabilities: []*ocsf.Vulnerability{
						{
							AffectedCode:  g.mapAffectedCode(res),
							Cwe:           g.mapCWE(ruleID, ruleToTools, taxasByCWEID),
							Desc:          ptr.Ptr(desc),
							FirstSeenTime: &now,
							LastSeenTime:  &now,
							Severity:      ptr.Ptr(severityID.String()),
							Title:         ptr.Ptr(title),
							VendorName:    ptr.Ptr("gosec"),
						},
					},
				},
			)
		}
		vulns = append(vulns, runVulns...)
	}

	logger.Debug(
		"successfully parsed raw sarif findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_sarif_findings", len(vulns)),
	)

	return vulns, nil
}

func (*gosecTransformer) mapSeverity(sarifResLevel sarifschemav210.ResultLevel) ocsf.VulnerabilityFinding_SeverityId {
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

func (g *gosecTransformer) mapDataSource(
	ctx context.Context,
	locations []sarifschemav210.Location,
) (string, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)

	for _, location := range locations {
		if location.PhysicalLocation == nil ||
			location.PhysicalLocation.ArtifactLocation == nil ||
			location.PhysicalLocation.ArtifactLocation.Uri == nil {
			continue
		}

		targetType, ok := map[TargetType]ocsffindinginfo.DataSource_TargetType{
			TargetTypeRepository: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		}[g.targetType]
		if !ok {
			targetType = ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED
		}

		dataSource := ocsffindinginfo.DataSource{
			TargetType: targetType,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      *location.PhysicalLocation.ArtifactLocation.Uri,
			},
			SourceCodeMetadata: targetMetadata.SourceCodeMetadata,
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

func (g *gosecTransformer) mapConfidence(
	ruleID string,
	ruleToTools map[string]sarifschemav210.ReportingDescriptor,
) (confidence ocsf.VulnerabilityFinding_ConfidenceId) {
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

func (g *gosecTransformer) mapTitleDesc(
	res sarifschemav210.Result,
	ruleToTools map[string]sarifschemav210.ReportingDescriptor,
) (title string, descr string) {
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

func (g *gosecTransformer) mapAffectedCode(res sarifschemav210.Result) []*ocsf.AffectedCode {
	var affectedCode = make([]*ocsf.AffectedCode, 0)
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
			ac.File.Name = *location.PhysicalLocation.ArtifactLocation.Uri
			ac.File.Path = ptr.Ptr(fmt.Sprintf("file://%s", *location.PhysicalLocation.ArtifactLocation.Uri))
		}

		if physicalLocation.Region != nil {
			ac.StartLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.StartLine))
			ac.EndLine = ptr.Ptr(int32(*location.PhysicalLocation.Region.EndLine))
		}

		if ac != (&ocsf.AffectedCode{}) {
			affectedCode = append(affectedCode, ac)
		}
	}

	return affectedCode
}

func (g *gosecTransformer) mapCWE(
	ruleID string,
	ruleToTools map[string]sarifschemav210.ReportingDescriptor,
	taxasByCWEID map[string]sarifschemav210.ReportingDescriptor,
) *ocsf.Cwe {
	cwe := &ocsf.Cwe{}

	rule, ok := ruleToTools[ruleID]
	if !ok {
		return nil
	}

	for _, rel := range rule.Relationships {
		cwe.Uid = *rel.Target.Id
		taxa, ok := taxasByCWEID[cwe.Uid]
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
