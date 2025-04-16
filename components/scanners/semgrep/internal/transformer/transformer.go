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
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
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
	logger := component.
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
	transformer, err := sarif.NewTransformer(&report,
		"",
		sarif.TargetTypeRepository,
		g.clock, sarif.RealUUIDProvider{})
	if err != nil {
		return nil, err
	}
	ocsfVulns, err := transformer.ToOCSF(ctx)
	if err != nil {
		return nil, err
	}
	return g.AddMetadataToDatasources(ctx, ocsfVulns)
}

func (g *semgrepTransformer) AddMetadataToDatasources(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	for _, f := range findings {
		for i, source := range f.FindingInfo.DataSources {
			dataSource := ocsffindinginfo.DataSource{}
			if err := protojson.Unmarshal([]byte(source), &dataSource); err != nil {
				return nil, errors.Errorf("could not unmarshal datasource %s, err:%w", source, err)
			}
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
