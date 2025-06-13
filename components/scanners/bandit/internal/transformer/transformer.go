package transformer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/scanners/bandit/internal/util/ptr"
)

type (
	// BanditTransformerOption allows customising the transformer.
	BanditTransformerOption func(b *BanditTransformer) error

	// BanditOut represents the output of a bandit run.
	BanditOut struct {
		Errors      []any           `json:"errors,omitempty"`
		GeneratedAt time.Time       `json:"generated_at,omitempty"`
		Metrics     any             `json:"metrics,omitempty"`
		Results     []*BanditResult `json:"results"`
	}

	// BanditCWE represents how Bandit shows a CWE.
	BanditCWE struct {
		ID   int    `json:"id,omitempty"`
		Link string `json:"link,omitempty"`
	}

	// BanditResult represents a Bandit Result.
	BanditResult struct {
		Code            string    `json:"code,omitempty"`
		ColOffset       int       `json:"col_offset,omitempty"`
		EndColOffset    int       `json:"end_col_offset,omitempty"`
		Filename        string    `json:"filename,omitempty"`
		IssueConfidence string    `json:"issue_confidence,omitempty"`
		IssueCwe        BanditCWE `json:"issue_cwe,omitempty"`
		IssueSeverity   string    `json:"issue_severity,omitempty"`
		IssueText       string    `json:"issue_text,omitempty"`
		LineNumber      int       `json:"line_number,omitempty"`
		LineRange       []int     `json:"line_range,omitempty"`
		MoreInfo        string    `json:"more_info,omitempty"`
		TestID          string    `json:"test_id,omitempty"`
		TestName        string    `json:"test_name,omitempty"`
	}

	// BanditTransformer represents the bandit output parser
	BanditTransformer struct {
		targetType     ocsffindinginfo.DataSource_TargetType
		clock          clockwork.Clock
		rawOutFilePath string
		fileContents   []byte
	}
)

var (
	// Generic errors

	// ErrNilClock is thrown when the option setclock is called with empty clock
	ErrNilClock = errors.Errorf("invalid nil clock")
	// ErrEmptyTarget is thrown when the option set target is called with empty target
	ErrEmptyTarget = errors.Errorf("invalid empty target")
	// ErrEmptyRawOutfilePath is thrown when the option raw outfile path is called with empty path
	ErrEmptyRawOutfilePath = errors.Errorf("invalid raw out file path")
	// ErrEmptyRawOutfileContents is thrown when the option raw outfile contents is called with empty contents
	ErrEmptyRawOutfileContents = errors.Errorf("empty raw out file contents")
	// ErrBadTargetType is thrown when the option set target type is called with an unspecified or empty target type
	ErrBadTargetType = errors.New("invalid empty target type")

	// Bandit Parser Specific Errors

	// ErrNoLineRange is thrown when bandit produces a finding without a line range
	ErrNoLineRange = errors.Errorf("bandit result does not contain a line range")
	// ErrBadDataSource is thrown when bandit produces a finding that cannot have a datasource (e.g. no filename)
	ErrBadDataSource = errors.Errorf("failed to marshal data source to JSON")
)

// BanditTransformerWithClock allows customising the underlying clock.
func BanditTransformerWithClock(clock clockwork.Clock) BanditTransformerOption {
	return func(g *BanditTransformer) error {
		if clock == nil {
			return ErrNilClock
		}
		g.clock = clock
		return nil
	}
}

// BanditTransformerWithTarget allows customising the underlying target type.
func BanditTransformerWithTarget(target ocsffindinginfo.DataSource_TargetType) BanditTransformerOption {
	return func(g *BanditTransformer) error {
		if target == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED {
			return ErrEmptyTarget
		}
		g.targetType = target
		return nil
	}
}

// BanditRawOutFilePath allows customising the underlying raw out file path.
func BanditRawOutFilePath(path string) BanditTransformerOption {
	return func(g *BanditTransformer) error {
		if path == "" {
			return ErrEmptyRawOutfilePath
		}
		g.rawOutFilePath = path
		return nil
	}
}

// BanditRawOutFileContents allows customising the underlying raw out file contents.
func BanditRawOutFileContents(contents []byte) BanditTransformerOption {
	return func(g *BanditTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		g.fileContents = contents
		return nil
	}
}

// New returns a new bandit transformer.
func New(opts ...BanditTransformerOption) (*BanditTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"BANDIT_RAW_OUT_FILE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	tt, err := env.GetOrDefault(
		"BANDIT_TARGET_TYPE",
		ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := BanditTransformer{
		rawOutFilePath: rawOutFilePath,
		targetType:     ocsffindinginfo.DataSource_TargetType(ocsffindinginfo.DataSource_TargetType_value[tt]),
		clock:          clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}
	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (b *BanditTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw bandit output...")
	if b.fileContents == nil {
		inFile, err := os.ReadFile(b.rawOutFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.Errorf("raw output file '%s' not found", b.rawOutFilePath)
			}
			return nil, errors.Errorf("failed to read raw output file '%s': %w", b.rawOutFilePath, err)
		}
		b.fileContents = inFile
	}
	var results BanditOut
	if err := json.Unmarshal(b.fileContents, &results); err != nil {
		return nil, errors.Errorf("could not unmarshal bandit output, err: %w", err)
	}
	vulns := make([]*ocsf.VulnerabilityFinding, 0)

	for _, res := range results.Results {
		v, err := b.parseResult(ctx, res)
		if err != nil {
			return nil, errors.Errorf("could not parse bandit result, err: %w", err)
		}
		vulns = append(vulns, v)
	}

	logger.Debug(
		"successfully parsed raw bandit findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_bandit_findings", len(vulns)),
	)
	return vulns, nil
}

func (b *BanditTransformer) parseResult(ctx context.Context, r *BanditResult) (*ocsf.VulnerabilityFinding, error) {
	now := b.clock.Now().Unix()
	confidence := fmt.Sprintf("CONFIDENCE_ID_%s", r.IssueConfidence)
	confidenceID := ocsf.VulnerabilityFinding_ConfidenceId_value[confidence]
	severity := fmt.Sprintf("SEVERITY_ID_%s", r.IssueSeverity)
	severityID := ocsf.VulnerabilityFinding_SeverityId_value[severity]
	dataSource, err := b.mapDataSource(ctx, r)
	if err != nil {
		return nil, errors.Errorf("failed to map data source: %w", err)
	}

	affectedCode, err := b.mapCode(r)
	if err != nil {
		return nil, errors.Errorf("failed to map code: %w", err)
	}

	return &ocsf.VulnerabilityFinding{
		ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
		ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
		CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
		ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
		ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),

		Confidence:   &confidence,
		ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_ConfidenceId(confidenceID)),
		Count:        ptr.Ptr(int32(1)),
		FindingInfo: &ocsf.FindingInfo{
			CreatedTime: &now,
			DataSources: []string{
				dataSource,
			},
			Desc:          ptr.Ptr(fmt.Sprintf("%s:%s", r.TestName, r.IssueText)),
			FirstSeenTime: &now,
			LastSeenTime:  &now,
			ModifiedTime:  &now,
			ProductUid:    ptr.Ptr("bandit"),
			Title:         r.IssueText,
			Uid:           r.TestID,
		},
		Message:    &r.IssueText,
		Severity:   &severity,
		SeverityId: ocsf.VulnerabilityFinding_SeverityId(severityID),
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
				AffectedCode:  affectedCode,
				Cwe:           b.mapCWE(&r.IssueCwe),
				Desc:          &r.IssueText,
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				Severity:      &severity,
				Title:         &r.IssueText,
				VendorName:    ptr.Ptr("bandit"),
			},
		},
	}, nil
}

func (*BanditTransformer) mapCode(r *BanditResult) ([]*ocsf.AffectedCode, error) {
	var ac []*ocsf.AffectedCode
	if len(r.LineRange) == 0 {
		return nil, ErrNoLineRange
	}
	ac = append(ac,
		&ocsf.AffectedCode{
			EndLine:   ptr.Ptr(int32(r.LineRange[0])),
			StartLine: ptr.Ptr(int32(r.LineRange[len(r.LineRange)-1])),
			File: &ocsf.File{
				Name: filepath.Base(r.Filename),
				Path: ptr.Ptr(fmt.Sprintf("file://%s", r.Filename)),
			},
		},
	)
	return ac, nil
}

// Future TODO: do a DB query and enrich the CWE with info such as description, current state(valid/not valid) etc
func (*BanditTransformer) mapCWE(r *BanditCWE) *ocsf.Cwe {
	return &ocsf.Cwe{
		SrcUrl: &r.Link,
		Uid:    fmt.Sprintf("%d", r.ID),
	}
}

func (b *BanditTransformer) mapDataSource(ctx context.Context, r *BanditResult) (string, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	endLine := uint32(r.LineNumber)
	if len(r.LineRange) > 0 {
		endLine = uint32(r.LineRange[len(r.LineRange)-1])
	}
	if r.Filename == "" {
		return "", errors.Errorf("%w, there is a finding without a filename", ErrBadDataSource)
	}

	dataSource := ocsffindinginfo.DataSource{
		TargetType: b.targetType,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      r.Filename,
		},
		LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   uint32(r.LineNumber),
				EndLine:     endLine,
				StartColumn: uint32(r.ColOffset),
				EndColumn:   uint32(r.EndColOffset),
			},
		},
		SourceCodeMetadata: targetMetadata.SourceCodeMetadata,
	}
	toBytes, err := protojson.Marshal(&dataSource)
	if err != nil {
		return "", errors.Errorf("%w err:%w", ErrBadDataSource, err)
	}
	return string(toBytes), nil
}
