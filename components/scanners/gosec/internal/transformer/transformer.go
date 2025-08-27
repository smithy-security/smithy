package transformer

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/scanners/gosec/internal/config"
)

type (
	// FindingsConverter abstracts how to convert sarif findings to OCSF.
	FindingsConverter interface {
		ToOCSF(ctx context.Context, datasource *ocsffindinginfo.DataSource) ([]*ocsf.VulnerabilityFinding, error)
	}

	// TargetType represents the target type.
	TargetType string

	gosecTransformer struct {
		cfg config.Config
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// New returns a new gosec transformer.
func New(cfg config.Config) (*gosecTransformer, error) {
	if cfg.RawOutFilePath == "" {
		return nil, errors.New("invalid empty raw output file")
	}

	if _, err := os.Stat(cfg.RawOutFilePath); errors.Is(err, os.ErrNotExist) {
		return nil, errors.Errorf("%s: %w", cfg.RawOutFilePath, err)
	}

	return &gosecTransformer{cfg: cfg}, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *gosecTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw sarif findings to ocsf vulnerability findings...")

	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to initialize uuid provider: %w", err)
	}

	fileContents, err := os.ReadFile(g.cfg.RawOutFilePath)
	if err != nil {
		return nil, errors.Errorf("could not read file %s", g.cfg.RawOutFilePath)
	}

	if len(fileContents) == 0 {
		return []*ocsf.VulnerabilityFinding{}, nil
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(fileContents); err != nil {
		return nil, errors.Errorf("failed to parse raw findings output: %w", err)
	}

	converter, err := sarif.NewTransformer(
		&report,
		"",
		g.cfg.Clock,
		guidProvider,
		true,
		component.TargetMetadataFromCtx(ctx),
	)
	if err != nil {
		return nil, errors.Errorf("could not initialise Sarif to OCSF transformer: %w", err)
	}

	vulns, err := converter.ToOCSF(ctx)
	switch {
	case err != nil:
		return nil, errors.Errorf("failed to parse raw gosec findings: %w", err)
	case len(vulns) == 0:
		logger.Debug("no findings to parse, skipping")
		return nil, nil
	}

	logger.Debug(
		"successfully parsed raw sarif findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_sarif_findings", len(vulns)),
	)

	return vulns, nil
}
