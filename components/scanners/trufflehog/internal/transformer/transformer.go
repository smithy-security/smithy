package transformer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/new-components/scanner/trufflehog/internal/util/ptr"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	TrufflehogOut struct {
		SourceMetadata        SourceMetadata `json:"SourceMetadata,omitempty"`
		SourceID              int            `json:"SourceID,omitempty"`
		SourceType            int            `json:"SourceType,omitempty"`
		SourceName            string         `json:"SourceName,omitempty"`
		DetectorType          int            `json:"DetectorType,omitempty"`
		DetectorName          string         `json:"DetectorName,omitempty"`
		DetectorDescription   string         `json:"DetectorDescription,omitempty"`
		DecoderName           string         `json:"DecoderName,omitempty"`
		Verified              bool           `json:"Verified,omitempty"`
		VerificationFromCache bool           `json:"VerificationFromCache,omitempty"`
		Raw                   string         `json:"Raw,omitempty"`
		RawV2                 string         `json:"RawV2,omitempty"`
		Redacted              string         `json:"Redacted,omitempty"`
		ExtraData             any            `json:"ExtraData,omitempty"`
		StructuredData        any            `json:"StructuredData,omitempty"`
	}

	Filesystem struct {
		File string `json:"file,omitempty"`
		Line int    `json:"line,omitempty"`
	}

	Data struct {
		Filesystem Filesystem `json:"Filesystem,omitempty"`
	}

	SourceMetadata struct {
		Data Data `json:"Data,omitempty"`
	}

	// TrufflehogTransformerOption allows customising the transformer.
	TrufflehogTransformerOption func(g *trufflehogTransformer) error

	trufflehogTransformer struct {
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

// ParseMultiJSONMessages provides method to parse tool results in JSON format.
// It allows for parsing single JSON files with multiple JSON messages in them.
func ParseMultiJSONMessages(in []byte) ([]*TrufflehogOut, error) {
	dec := json.NewDecoder(strings.NewReader(string(in)))
	var res []*TrufflehogOut
	for {
		var item TrufflehogOut
		err := dec.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return res, err
		}
		if item.DecoderName == "" {
			return nil, errors.Errorf("failed to decode item:: %#v", item)
		}
		res = append(res, &item)
	}
	return res, nil
}

// TrufflehogTransformerWithClock allows customising the underlying clock.
func TrufflehogTransformerWithClock(clock clockwork.Clock) TrufflehogTransformerOption {
	return func(g *trufflehogTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// TrufflehogTransformerWithTarget allows customising the underlying target type.
func TrufflehogTransformerWithTarget(target ocsffindinginfo.DataSource_TargetType) TrufflehogTransformerOption {
	return func(g *trufflehogTransformer) error {
		if target == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// TrufflehogRawOutFilePath allows customising the underlying raw out file path.
func TrufflehogRawOutFilePath(path string) TrufflehogTransformerOption {
	return func(g *trufflehogTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// TrufflehogRawOutFileContents allows customising the underlying raw out file contents.
func TrufflehogRawOutFileContents(contents []byte) TrufflehogTransformerOption {
	return func(g *trufflehogTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		g.fileContents = contents
		return nil
	}
}

// New returns a new gosec transformer.
func New(opts ...TrufflehogTransformerOption) (*trufflehogTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"TRUFFLEHOG_RAW_OUT_FILE_PATH",
		"trufflehog.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"TRUFFLEHOG_TARGET_TYPE",
		ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := trufflehogTransformer{
		rawOutFilePath: rawOutFilePath,
		targetType:     ocsffindinginfo.DataSource_TargetType(ocsffindinginfo.DataSource_TargetType_value[target]),
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
	case t.targetType == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED:
		return nil, errors.New("invalid empty target type")
	}

	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *trufflehogTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw trufflehog output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	truffleResults, err := ParseMultiJSONMessages(b)
	if err != nil {
		return nil, errors.Errorf("could not parse trufflehog file with multiple messages, err: %w", err)
	}

	findings, err := g.parseFindings(truffleResults)
	if err != nil {
		return nil, errors.Errorf("one or more findings failed to transform err: %w", err)
	}
	logger.Debug("successfully transformed", slog.Int("num_findings", len(findings)))
	return findings, err
}

func (t *trufflehogTransformer) parseFindings(out []*TrufflehogOut) ([]*ocsf.VulnerabilityFinding, error) {
	vulns := make([]*ocsf.VulnerabilityFinding, 0, len(out))
	now := t.clock.Now().Unix()

	for _, finding := range out {
		confidenceID := ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW
		if finding.Verified {
			confidenceID = ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH
		}
		confidence := ocsf.VulnerabilityFinding_ConfidenceId_name[int32(confidenceID)]
		dataSource, err := t.mapDataSource(*finding)
		if err != nil {
			return nil, errors.Errorf("could not map datasource for finding %#v, err:%w", finding, err)
		}
		affectedCode := t.mapAffectedCode(*finding)
		description := fmt.Sprintf("Trufflehog found hardcoded credentials (Redacted):%s\n", finding.Redacted)

		vulns = append(vulns,
			&ocsf.VulnerabilityFinding{
				ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),

				Confidence:   &confidence,
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_ConfidenceId(confidenceID)),
				Count:        ptr.Ptr(int32(1)),
				Message:      &description,
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime: &now,
					DataSources: []string{
						dataSource,
					},
					Desc:          &description,
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr.Ptr("bandit"),
					Title:         fmt.Sprintf("%s\n%s:%s", finding.SourceName, finding.DecoderName, finding.DetectorName),
					Uid:           fmt.Sprintf("%d:%d:%d", finding.SourceID, finding.SourceType, finding.DetectorType),
				},
				Severity:   ptr.Ptr(ocsf.VulnerabilityFinding_SeverityId_name[int32(ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN)]),
				SeverityId: ocsf.VulnerabilityFinding_SeverityId(ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN),
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

						Severity:     ptr.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
						AffectedCode: []*ocsf.AffectedCode{affectedCode},
						Cwe: &ocsf.Cwe{
							SrcUrl:  ptr.Ptr("https://cwe.mitre.org/data/definitions/798.html"),
							Uid:     "798",
							Caption: ptr.Ptr("Use of Hard-coded Credentials"),
						},
						Desc:          &description,
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						Title:         ptr.Ptr(fmt.Sprintf("%s\n%s:%s", finding.SourceName, finding.DecoderName, finding.DetectorName)),
					},
				},
			})
	}
	return vulns, nil
}

func (t *trufflehogTransformer) mapDataSource(location TrufflehogOut) (string, error) {
	if location.SourceMetadata.Data.Filesystem.File == "" {
		return "", errors.Errorf("unsupported trufflehog findings with empty file entry detected, finding %#v", location)
	}
	dataSource := ocsffindinginfo.DataSource{
		TargetType: t.targetType,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      location.SourceMetadata.Data.Filesystem.File,
		},
		LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: uint32(location.SourceMetadata.Data.Filesystem.Line),
			},
		},
	}
	toBytes, err := protojson.Marshal(&dataSource)
	if err != nil {
		return "", errors.Errorf("%w err:%w", ErrBadDataSource, err)
	}
	return string(toBytes), nil
}

func (t *trufflehogTransformer) mapAffectedCode(location TrufflehogOut) *ocsf.AffectedCode {
	result := ocsf.AffectedCode{}
	if location.SourceMetadata.Data.Filesystem.File != "" {
		result.File = &ocsf.File{
			Name: filepath.Base(location.SourceMetadata.Data.Filesystem.File),
			Path: ptr.Ptr(fmt.Sprintf("file://%s", location.SourceMetadata.Data.Filesystem.File)),
		}
		result.StartLine = ptr.Ptr(int32(location.SourceMetadata.Data.Filesystem.Line))
	}
	return &result
}
