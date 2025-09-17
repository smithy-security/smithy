package transformer

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

type (

	// OSVScannerTransformerOption allows customising the transformer.
	OSVScannerTransformerOption func(b *OSVScannerTransformer) error

	// OSVScannerTransformer represents the osv-scanner output parser
	OSVScannerTransformer struct {
		targetType    ocsffindinginfo.DataSource_TargetType
		clock         clockwork.Clock
		rawOutFile    string
		fileContents  []byte
		workspacePath string
	}
)

var (

	// Generic errors

	// ErrNilClock is thrown when the option setclock is called with empty clock
	ErrNilClock = errors.Errorf("invalid nil clock")
	// ErrEmptyRawOutfileContents is thrown when the option raw outfile contents is called with empty contents
	ErrEmptyRawOutfileContents = errors.Errorf("empty raw out file contents")

	// ErrMalformedSARIFfile is returned when the SARIF file given to this transformer is not valid JSON
	ErrMalformedSARIFfile = errors.Errorf("failed to parse raw SARIF output")
	// OSVScanner Parser Specific Errors
	// ErrEmptyPath is thrown when called with an empty project root
	ErrEmptyPath = errors.Errorf("called with an empty project root")
	// ErrNoLineRange is thrown when osv-scanner produces a finding without a line range
	ErrNoLineRange = errors.Errorf("osv-scanner result does not contain a line range")
	// ErrBadDataSource is thrown when osv-scanner produces a finding that cannot have a datasource (e.g. no filename)
	ErrBadDataSource = errors.Errorf("failed to marshal data source to JSON")
	// ErrCouldNotFindPackage is thrown when nancy cannot find the dependency in any go.mod files
	ErrCouldNotFindPackage = errors.Errorf("could not find package")

	// ErrConstructPath is thrown when it cannot construct path for affected code
	ErrConstructPath = errors.Errorf("could not construct path for affected code")
)

// OSVScannerTransformerWithClock allows customising the underlying clock.
func OSVScannerTransformerWithClock(clock clockwork.Clock) OSVScannerTransformerOption {
	return func(g *OSVScannerTransformer) error {
		if clock == nil {
			return ErrNilClock
		}
		g.clock = clock
		return nil
	}
}

// OSVScannerRawOutFileContents allows customising the underlying raw out file contents.
func OSVScannerRawOutFileContents(contents []byte) OSVScannerTransformerOption {
	return func(g *OSVScannerTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		g.fileContents = contents
		return nil
	}
}

// OSVScannerTransformerWithProjectRoot allows customising the path of the target project root
func OSVScannerTransformerWithProjectRoot(path string) OSVScannerTransformerOption {
	return func(g *OSVScannerTransformer) error {
		if path == "" {
			return ErrEmptyPath
		}
		g.workspacePath = path
		return nil
	}
}

// New returns a new osv-scanner transformer.
func New(opts ...OSVScannerTransformerOption) (*OSVScannerTransformer, error) {
	rawOutFile, err := env.GetOrDefault(
		"RAW_OUT_FILE",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	workspacePath, err := env.GetOrDefault(
		"WORKSPACE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	t := OSVScannerTransformer{
		clock:         clockwork.NewRealClock(),
		targetType:    ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		rawOutFile:    rawOutFile,
		workspacePath: workspacePath,
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}
	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (b *OSVScannerTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw osv-scanner output...")
	fileContents, err := os.ReadFile(b.rawOutFile)
	if err != nil {
		return nil, errors.Errorf("could not read file %s", b.rawOutFile)
	}
	if len(fileContents) == 0 {
		logger.Info("Scanner SARIF file is empty, exiting")
		return []*ocsf.VulnerabilityFinding{}, nil
	}
	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(fileContents); err != nil {
		return nil, errors.Errorf("%w: %w", ErrMalformedSARIFfile, err)
	}

	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to create guid provider: %w", err)
	}

	transformer, err := sarif.NewTransformer(
		&report,
		"",
		b.clock,
		guidProvider,
		false,
		component.TargetMetadataFromCtx(ctx),
		b.workspacePath,
	)
	if err != nil {
		return nil, err
	}

	vulns, err := transformer.ToOCSF(ctx)
	if err != nil {
		return nil, err
	}
	vulns, err = b.AddMetadataToDatasources(ctx, vulns)
	if err != nil {
		return nil, err
	}
	logger.Debug(
		"successfully parsed raw osv-scanner findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_findings", len(vulns)),
	)
	return vulns, nil
}

func (b *OSVScannerTransformer) AddMetadataToDatasources(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	for _, f := range findings {
		for i, source := range f.FindingInfo.DataSources {
			dataSource := ocsffindinginfo.DataSource{}
			if err := protojson.Unmarshal([]byte(source), &dataSource); err != nil {
				return nil, errors.Errorf("could not unmarshal datasource %s, err:%w", source, err)
			}
			dataSource.TargetType = ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY
			dataSource.SourceCodeMetadata = targetMetadata.SourceCodeMetadata
			metadataSource, err := protojson.Marshal(&dataSource)
			if err != nil {
				return nil, errors.Errorf("could not marshal new datasource with metdata err:%w", err)
			}
			f.FindingInfo.DataSources[i] = string(metadataSource)
		}
	}
	return findings, nil
}
