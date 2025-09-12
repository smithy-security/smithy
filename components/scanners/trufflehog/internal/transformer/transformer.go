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
	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
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
	TrufflehogTransformerOption func(t *trufflehogTransformer) error

	trufflehogTransformer struct {
		targetType          ocsffindinginfo.DataSource_TargetType
		clock               clockwork.Clock
		rawOutFilePath      string
		fileContents        []byte
		stripFilePathPrefix string
	}
)

var (
	// Generic errors

	// ErrEmptyRawOutfileContents is thrown when the option raw outfile contents is called with empty contents
	ErrEmptyRawOutfileContents = errors.Errorf("empty raw out file contents")

	// Parser Specific Errors

	// ErrBadDataSource is thrown when parser produces a finding that cannot have a datasource (e.g. no filename)
	ErrBadDataSource = errors.Errorf("failed to marshal data source to JSON")

	// ErrPrefixNotInPath is thrown when the path does not have the expected prefix
	ErrPrefixNotInPath = errors.Errorf("path does not have expected prefix")
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
	return func(t *trufflehogTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		t.clock = clock
		return nil
	}
}

// TrufflehogTransformerWithTarget allows customising the underlying target type.
func TrufflehogTransformerWithTarget(target ocsffindinginfo.DataSource_TargetType) TrufflehogTransformerOption {
	return func(t *trufflehogTransformer) error {
		if target == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED {
			return errors.Errorf("invalid empty target")
		}
		t.targetType = target
		return nil
	}
}

// TrufflehogRawOutFilePath allows customising the underlying raw out file path.
func TrufflehogRawOutFilePath(path string) TrufflehogTransformerOption {
	return func(t *trufflehogTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		t.rawOutFilePath = path
		return nil
	}
}

// TrufflehogRawOutFileContents allows customising the underlying raw out file contents.
func TrufflehogRawOutFileContents(contents []byte) TrufflehogTransformerOption {
	return func(t *trufflehogTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		t.fileContents = contents
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

	stripFilePathPrefix, err := env.GetOrDefault(
		"TRUFFLEHOG_SOURCE_CODE_WORKSPACE",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, errors.Errorf("could not lookup environment variable for '%s': %w", "TRUFFLEHOG_SOURCE_CODE_WORKSPACE", err)
	}

	t := trufflehogTransformer{
		rawOutFilePath:      rawOutFilePath,
		targetType:          ocsffindinginfo.DataSource_TargetType(ocsffindinginfo.DataSource_TargetType_value[target]),
		clock:               clockwork.NewRealClock(),
		stripFilePathPrefix: stripFilePathPrefix,
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
func (t *trufflehogTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("Preparing to parse raw trufflehog output...")

	b, err := os.ReadFile(t.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", t.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", t.rawOutFilePath, err)
	}

	truffleResults, err := ParseMultiJSONMessages(b)
	if err != nil {
		return nil, errors.Errorf("could not parse trufflehog file with multiple messages, err: %w", err)
	}

	findings, err := t.parseFindings(ctx, truffleResults)
	if err != nil {
		return nil, errors.Errorf("one or more findings failed to transform, err: %w", err)
	}

	logger.Debug("Successfully transformed", slog.Int("num_findings", len(findings)))
	return findings, err
}

func (t *trufflehogTransformer) parseFindings(ctx context.Context, out []*TrufflehogOut) ([]*ocsf.VulnerabilityFinding, error) {

	var (
		logger = componentlogger.LoggerFromContext(ctx)
		vulns  = make([]*ocsf.VulnerabilityFinding, 0, len(out))
		now    = t.clock.Now().Unix()
	)

	for _, finding := range out {
		confidenceID := ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW

		if finding.Verified {
			confidenceID = ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH
		}
		confidence := ocsf.VulnerabilityFinding_ConfidenceId_name[int32(confidenceID)]

		path := finding.SourceMetadata.Data.Filesystem.File
		if path == "" {
			return nil, errors.Errorf("unsupported trufflehog findings with empty file entry detected, finding %#v", finding)
		}

		// Please note if you pass empty string to clean it will return ".". And then that will fail futher
		// down in filepath.Rel(...). Hence why I chose to check for absPath == "" first in the lines above
		cleanedPath := filepath.Clean(path)
		cleanedPrefix := filepath.Clean(t.stripFilePathPrefix)

		logger.Debug("Checking if absolute path has the prefix",
			slog.String("path", cleanedPath),
			slog.String("prefix_path", cleanedPrefix),
		)

		if !strings.HasPrefix(cleanedPath, cleanedPrefix) {
			return nil, errors.Errorf("%w: absolute path: %q, and prefix: %q", ErrPrefixNotInPath, cleanedPath, t.stripFilePathPrefix)
		}

		logger.Debug("Getting relative path...")

		relativePath, err := filepath.Rel(cleanedPrefix, cleanedPath)
		if err != nil {
			return nil, errors.Errorf("could not get relative path from path %s using prefix %q", cleanedPath, cleanedPrefix)
		}

		logger.Debug("Found paths...",
			slog.String("path", cleanedPath),
			slog.String("prefix_path", cleanedPrefix),
			slog.String("relative_path", relativePath),
		)

		fileSystemLine := finding.SourceMetadata.Data.Filesystem.Line

		dataSource, err := t.mapDataSource(ctx, relativePath, fileSystemLine)
		if err != nil {
			return nil, errors.Errorf("could not map datasource for finding %#v, err:%w", finding, err)
		}

		affectedCode := &ocsf.AffectedCode{
			File: &ocsf.File{
				Name: filepath.Base(relativePath),
				Path: utils.Ptr(fmt.Sprintf("file://%s", relativePath)),
			},
			StartLine: utils.Ptr(int32(fileSystemLine)),
		}

		description := fmt.Sprintf("Trufflehog found hardcoded credentials (Redacted):%s\n", finding.Redacted)

		vulns = append(vulns,
			&ocsf.VulnerabilityFinding{
				ActivityName: utils.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				ClassName:    utils.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),

				Confidence:   &confidence,
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_ConfidenceId(confidenceID)),
				Count:        utils.Ptr(int32(1)),
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
					ProductUid:    utils.Ptr("trufflehog"),
					Title:         fmt.Sprintf("%s\n%s:%s", finding.SourceName, finding.DecoderName, finding.DetectorName),
					Uid:           fmt.Sprintf("%d:%d:%d", finding.SourceID, finding.SourceType, finding.DetectorType),
				},
				Severity:   utils.Ptr(ocsf.VulnerabilityFinding_SeverityId_name[int32(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH)]),
				SeverityId: ocsf.VulnerabilityFinding_SeverityId(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH),
				StartTime:  &now,
				Status:     utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW.String()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Time:       now,
				TypeUid: int64(
					ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
						100 +
						ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
				),
				Vulnerabilities: []*ocsf.Vulnerability{
					{

						Severity:     utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
						AffectedCode: []*ocsf.AffectedCode{affectedCode},
						Cwe: &ocsf.Cwe{
							SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/798.html"),
							Uid:     "798",
							Caption: utils.Ptr("Use of Hard-coded Credentials"),
						},
						Desc:          &description,
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						Title:         utils.Ptr(fmt.Sprintf("%s\n%s:%s", finding.SourceName, finding.DecoderName, finding.DetectorName)),
						VendorName:    utils.Ptr("trufflehog"),
					},
				},
			})
	}
	return vulns, nil
}

func (t *trufflehogTransformer) mapDataSource(ctx context.Context, relativePath string, line int) (string, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	dataSource := ocsffindinginfo.DataSource{
		TargetType: t.targetType,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      fmt.Sprintf("file://%s", relativePath),
		},
		LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: uint32(line),
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
