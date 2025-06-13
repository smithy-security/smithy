package transformer

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

const TargetTypeRepository TargetType = "repository"

type (
	// SemgrepTransformerOption allows customising the transformer.
	SemgrepTransformerOption func(g *semgrepTransformer) error

	// TargetType represents the target type.
	TargetType string

	semgrepTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// SemgrepTransformerWithClock allows customising the underlying clock.
func SemgrepTransformerWithClock(clock clockwork.Clock) SemgrepTransformerOption {
	return func(g *semgrepTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// SemgrepTransformerWithTarget allows customising the underlying target type.
func SemgrepTransformerWithTarget(target TargetType) SemgrepTransformerOption {
	return func(g *semgrepTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// SemgrepRawOutFilePath allows customising the underlying raw out file path.
func SemgrepRawOutFilePath(path string) SemgrepTransformerOption {
	return func(g *semgrepTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new semgrep transformer.
func New(opts ...SemgrepTransformerOption) (*semgrepTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"SEMGREP_RAW_OUT_FILE_PATH",
		"semgrep.sarif.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"SEMGREP_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := semgrepTransformer{
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
func (g *semgrepTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw semgrep output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw semgrep output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw semgrep output!",
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

	transformer, err := sarif.NewTransformer(&report, "", g.clock, guidProvider, true)
	if err != nil {
		return nil, err
	}
	ocsfFindings, err := transformer.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
	if err != nil {
		return nil, err
	}
	return g.PostProcessing(ctx, ocsfFindings)
}

func (g *semgrepTransformer) PostProcessing(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	for _, finding := range findings {
		newMsg := strings.ReplaceAll(*finding.Message, "💎 Enable cross-file analysis and Pro rules for free at sg.run/pro", "")
		finding.Message = &newMsg
	}
	return findings, nil
}
