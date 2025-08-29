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
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// TargetTypeContainer refers to the type of asset scanned by trivy that
// produced the results
const TargetTypeContainer TargetType = "container"

type (
	// TrivyTransformerOption allows customising the transformer.
	TrivyTransformerOption func(g *TrivyTransformer) error

	// TargetType represents the target type.
	TargetType string

	// TrivyTransformer parses results from a Trivy scan and converts them into
	// OCSF
	TrivyTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// TrivyTransformerWithClock allows customising the underlying clock.
func TrivyTransformerWithClock(clock clockwork.Clock) TrivyTransformerOption {
	return func(g *TrivyTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// TrivyTransformerWithTarget allows customising the underlying target type.
func TrivyTransformerWithTarget(target TargetType) TrivyTransformerOption {
	return func(g *TrivyTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// TrivyRawOutFilePath allows customising the underlying raw out file path.
func TrivyRawOutFilePath(path string) TrivyTransformerOption {
	return func(g *TrivyTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new trivy transformer.
func New(opts ...TrivyTransformerOption) (*TrivyTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"TRIVY_RAW_OUT_FILE_PATH",
		"trivy.sarif.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"TRIVY_TARGET_TYPE",
		TargetTypeContainer.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := TrivyTransformer{
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
func (t *TrivyTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw trivy output...")

	b, err := os.ReadFile(t.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", t.rawOutFilePath)
		}

		return nil, errors.Errorf("failed to read raw output file '%s': %w", t.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw trivy output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw trivy output!",
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

	datasource := component.TargetMetadataFromCtx(ctx)
	datasourceJSON, err := protojson.Marshal(datasource)
	if err != nil {
		return nil, errors.Errorf("failed to marshal datasource to JSON: %w", err)
	}
	logger.Debug("datasource details", slog.String("datasource_json", string(datasourceJSON)))

	transformer, err := sarif.NewTransformer(&report, "docker", t.clock, guidProvider, true, datasource)
	if err != nil {
		return nil, err
	}

	return transformer.ToOCSF(ctx)
}
