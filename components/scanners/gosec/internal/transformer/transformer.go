package transformer

import (
	"context"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/new-components/scanners/gosec/internal/config"
)

const TargetTypeRepository TargetType = "repository"

type (
	// FindingsConverter abstracts how to convert sarif findings to OCSF.
	FindingsConverter interface {
		ToOCSF(ctx context.Context, datasource *ocsffindinginfo.DataSource) ([]*ocsf.VulnerabilityFinding, error)
	}

	// TargetType represents the target type.
	TargetType string

	gosecTransformer struct {
		targetType     TargetType
		rawOutFilePath string
		converter      FindingsConverter
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// New returns a new gosec transformer.
func New(converter FindingsConverter, cfg config.Config) (*gosecTransformer, error) {
	switch {
	case cfg.RawOutFilePath == "":
		return nil, errors.New("invalid empty raw output file")
	case cfg.TargetType == "":
		return nil, errors.New("invalid empty target type")
	case converter == nil:
		return nil, errors.New("invalid nil converter")
	}

	t := gosecTransformer{
		converter:      converter,
		rawOutFilePath: cfg.RawOutFilePath,
		targetType:     TargetType(cfg.TargetType),
	}

	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *gosecTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw sarif findings to ocsf vulnerability findings...")

	vulns, err := g.converter.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
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
