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
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	// SnykTransformerOption allows customising the transformer.
	SnykTransformerOption func(g *snykTransformer) error

	snykTransformer struct {
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

// SnykTransformerWithClock allows customising the underlying clock.
func SnykTransformerWithClock(clock clockwork.Clock) SnykTransformerOption {
	return func(g *snykTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// SnykRawOutFilePath allows customising the underlying raw out file path.
func SnykRawOutFilePath(path string) SnykTransformerOption {
	return func(g *snykTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new snyk transformer.
func New(opts ...SnykTransformerOption) (*snykTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"RAW_OUT_FILE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	t := snykTransformer{
		rawOutFilePath: rawOutFilePath,
		clock:          clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	if t.rawOutFilePath == "" {
		return nil, errors.New("invalid empty raw output file")
	}
	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *snykTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw snyk output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw snyk output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw snyk output!",
		slog.Int("num_sarif_runs", len(report.Runs)),
		slog.Int("num_sarif_results", func(runs []sarifschemav210.Run) int {
			var countRes = 0
			for _, run := range runs {
				countRes += len(run.Results)
			}
			return countRes
		}(report.Runs)),
	)

	logger.Debug("preparing to parse raw sarif findings to ocsf vulnerability findings...")
	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to create guid provider: %w", err)
	}

	transformer, err := sarif.NewTransformer(
		&report,
		"",
		g.clock,
		guidProvider,
		true,
		component.TargetMetadataFromCtx(ctx),
	)
	if err != nil {
		return nil, err
	}
	return transformer.ToOCSF(ctx)
}
