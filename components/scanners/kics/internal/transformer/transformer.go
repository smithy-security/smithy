package transformer

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	sarif "github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const TargetTypeRepository TargetType = "repository"

type (
	// KicsTransformerOption allows customising the transformer.
	KicsTransformerOption func(g *kicsTransformer) error

	// TargetType represents the target type.
	TargetType string

	kicsTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// KicsTransformerWithClock allows customising the underlying clock.
func KicsTransformerWithClock(clock clockwork.Clock) KicsTransformerOption {
	return func(g *kicsTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// KicsTransformerWithTarget allows customising the underlying target type.
func KicsTransformerWithTarget(target TargetType) KicsTransformerOption {
	return func(g *kicsTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// KicsRawOutFilePath allows customising the underlying raw out file path.
func KicsRawOutFilePath(path string) KicsTransformerOption {
	return func(g *kicsTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new kics transformer.
func New(opts ...KicsTransformerOption) (*kicsTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"KICS_RAW_OUT_FILE_PATH",
		"kics.sarif.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"KICS_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := kicsTransformer{
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
func (g *kicsTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw kics output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw kics output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw kics output!",
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
	transformer, err := sarif.NewTransformer(&report, "", g.clock, sarif.RealUUIDProvider{}, true)
	if err != nil {
		return nil, err
	}
	ocsfFindings, err := transformer.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
	if err != nil {
		return nil, err
	}
	return ocsfFindings, nil
}
