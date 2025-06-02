package transformer

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const TargetTypeRepository TargetType = "repository"

type (
	// MobSFTransformerOption allows customising the transformer.
	MobSFTransformerOption func(g *mobSFTransformer) error

	// TargetType represents the target type.
	TargetType string

	mobSFTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		rawOutFilePath string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// MobSFTransformerWithClock allows customising the underlying clock.
func MobSFTransformerWithClock(clock clockwork.Clock) MobSFTransformerOption {
	return func(g *mobSFTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// MobSFTransformerWithTarget allows customising the underlying target type.
func MobSFTransformerWithTarget(target TargetType) MobSFTransformerOption {
	return func(g *mobSFTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// MobSFRawOutFilePath allows customising the underlying raw out file path.
func MobSFRawOutFilePath(path string) MobSFTransformerOption {
	return func(g *mobSFTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new mobSF transformer.
func New(opts ...MobSFTransformerOption) (*mobSFTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"MOBSF_RAW_OUT_FILE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"MOBSF_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := mobSFTransformer{
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
func (g *mobSFTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw mobSF output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, errors.Errorf("failed to parse raw mobSF output: %w", err)
	}

	logger.Debug(
		"successfully parsed raw mobSF output!",
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
	)
	if err != nil {
		return nil, err
	}
	ocsfVulns, err := transformer.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
	if err != nil {
		return nil, err
	}
	// post processing, mosfscan titles are ruleIDs which is not good UX
	for _, v := range ocsfVulns {
		if v.FindingInfo.Desc != nil {
			ruleID := v.FindingInfo.Title
			v.FindingInfo.Title = *v.FindingInfo.Desc
			v.FindingInfo.Desc = utils.Ptr(fmt.Sprintf("%s\n rule-id:%s", *v.FindingInfo.Desc, ruleID))
		}
	}
	return ocsfVulns, nil
}
