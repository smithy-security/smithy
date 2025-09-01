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
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
)

// TargetTypeWebsite is the default type of target that ZAP will scan
const TargetTypeWebsite TargetType = "website"

type (
	// ZapTransformerOption allows customising the transformer.
	ZapTransformerOption func(g *ZapTransformer) error

	// TargetType represents the target type.
	TargetType string

	// ZapTransformer is used to convert a ZAP Sarif report into OCSF
	// vulnerability findings.
	ZapTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// ZapTransformerWithClock allows customising the underlying clock.
func ZapTransformerWithClock(clock clockwork.Clock) ZapTransformerOption {
	return func(g *ZapTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// ZapTransformerWithTarget allows customising the underlying target type.
func ZapTransformerWithTarget(target TargetType) ZapTransformerOption {
	return func(g *ZapTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// ZapRawOutFilePath allows customising the underlying raw out file path.
func ZapRawOutFilePath(path string) ZapTransformerOption {
	return func(g *ZapTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new zap transformer.
func New(opts ...ZapTransformerOption) (*ZapTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"ZAP_RAW_OUT_FILE_PATH",
		"zap.sarif.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"ZAP_TARGET_TYPE",
		TargetTypeWebsite.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := ZapTransformer{
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

func (z *ZapTransformer) readFile(file string) ([]byte, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found : %w", z.rawOutFilePath, err)
		}

		return nil, errors.Errorf("failed to read raw output file '%s': %w", z.rawOutFilePath, err)
	}

	return b, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (z *ZapTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := sdklogger.LoggerFromContext(ctx)
	logger.Debug("preparing to parse raw zap output...")

	b, err := z.readFile(z.rawOutFilePath)
	if err != nil {
		return nil, err
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw zap output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw zap output!",
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
	transformer, err := sarif.NewTransformer(
		&report, "", z.clock, nil, true, component.TargetMetadataFromCtx(ctx),
	)
	if err != nil {
		return nil, err
	}

	metrics := z.metrics(&report)
	logger.Info("ZAP result parser metrics",
		slog.Int("runs", metrics.runs),
		slog.Int("resultCount", metrics.resultCount),
		slog.String("paths", strings.Join(metrics.paths, ",")),
		slog.String("ruleIDs", strings.Join(metrics.ruleIDs, ",")),
	)

	return transformer.ToOCSF(ctx)
}

type metrics struct {
	runs        int
	resultCount int
	paths       []string
	ruleIDs     []string
}

func (*ZapTransformer) metrics(input *sarifschemav210.SchemaJson) metrics {
	var paths = make(map[string]struct{})
	var ruleIDs = make(map[string]struct{})
	var resultCount int

	for _, run := range input.Runs {
		for _, res := range run.Results {
			resultCount++
			if res.RuleId != nil {
				ruleIDs[*res.RuleId] = struct{}{}
			}
			for _, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.Uri != nil {
					paths[*loc.PhysicalLocation.ArtifactLocation.Uri] = struct{}{}
				}
			}
		}
	}
	// Convert sets to slices for display
	var pathList, ruleIDList []string
	for p := range paths {
		pathList = append(pathList, p)
	}
	for r := range ruleIDs {
		ruleIDList = append(ruleIDList, r)
	}

	return metrics{
		runs:        len(input.Runs),
		resultCount: resultCount,
		paths:       pathList,
		ruleIDs:     ruleIDList,
	}
}
