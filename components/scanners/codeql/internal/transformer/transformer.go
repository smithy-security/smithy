package transformer

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const TargetTypeRepository TargetType = "repository"

type (
	// CodeqlTransformerOption allows customising the transformer.
	CodeqlTransformerOption func(g *codeqlTransformer) error

	// TargetType represents the target type.
	TargetType string

	codeqlTransformer struct {
		targetType        TargetType
		clock             clockwork.Clock
		rawOutDirPathGlob string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// CodeqlTransformerWithClock allows customising the underlying clock.
func CodeqlTransformerWithClock(clock clockwork.Clock) CodeqlTransformerOption {
	return func(g *codeqlTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// CodeqlTransformerWithTarget allows customising the underlying target type.
func CodeqlTransformerWithTarget(target TargetType) CodeqlTransformerOption {
	return func(g *codeqlTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// CodeqlRawOutFilePath allows customising the underlying raw out file path.
func CodeqlRawOutDirGlob(glob string) CodeqlTransformerOption {
	return func(g *codeqlTransformer) error {
		if glob == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutDirPathGlob = glob
		return nil
	}
}

// New returns a new codeql transformer.
func New(opts ...CodeqlTransformerOption) (*codeqlTransformer, error) {
	rawOutDirPathGlob, err := env.GetOrDefault(
		"CODEQL_RAW_OUT_FILE_GLOB",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"CODEQL_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := codeqlTransformer{
		rawOutDirPathGlob: rawOutDirPathGlob,
		targetType:        TargetType(target),
		clock:             clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	switch {
	case t.rawOutDirPathGlob == "":
		return nil, errors.New("invalid empty raw output file")
	case t.targetType == "":
		return nil, errors.New("invalid empty target type")
	}

	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *codeqlTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.LoggerFromContext(ctx)
	logger.Debug("preparing to parse raw codeql output...")

	var result []*ocsf.VulnerabilityFinding

	matches, err := filepath.Glob(g.rawOutDirPathGlob)
	if err != nil {
		return nil, err
	}
	var fileNames []string
	for _, match := range matches {
		_, err := os.Stat(match)
		if err != nil {
			return nil, err
		}
		fileNames = append(fileNames, match)
	}

	for _, file := range fileNames {
		b, err := os.ReadFile(file)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.Errorf("raw output file '%s' not found", file)
			}
			return nil, errors.Errorf("failed to read raw output file '%s': %w", file, err)
		}

		var report sarifschemav210.SchemaJson
		if err := report.UnmarshalJSON(b); err != nil {
			return nil, errors.Errorf("failed to parse raw codeql output: %w", err)
		}

		logger.Debug(
			"successfully parsed raw codeql output!",
			slog.Int("num_sarif_runs", len(report.Runs)),
			slog.Int("num_sarif_results", func(runs []sarifschemav210.Run) int {
				var countRes = 0
				for _, run := range runs {
					countRes += len(run.Results)
				}
				return countRes
			}(report.Runs)),
		)

		guidProvider, err := sarif.NewBasicStableUUIDProvider()
		if err != nil {
			return nil, errors.Errorf("failed to create guid provider: %w", err)
		}

		transformer, err := sarif.NewTransformer(&report, "", g.clock, guidProvider, true)
		if err != nil {
			return nil, err
		}
		vulns, err := transformer.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
		if err != nil {
			return nil, err
		}
		result = append(result, vulns...)
	}
	return result, nil
}
