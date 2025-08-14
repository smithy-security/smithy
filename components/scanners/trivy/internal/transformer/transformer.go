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
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

const TargetTypeContainer TargetType = "container"

type (
	// TrivyTransformerOption allows customising the transformer.
	TrivyTransformerOption func(g *trivyTransformer) error

	// TargetType represents the target type.
	TargetType string

	trivyTransformer struct {
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
	return func(g *trivyTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// TrivyTransformerWithTarget allows customising the underlying target type.
func TrivyTransformerWithTarget(target TargetType) TrivyTransformerOption {
	return func(g *trivyTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// TrivyRawOutFilePath allows customising the underlying raw out file path.
func TrivyRawOutFilePath(path string) TrivyTransformerOption {
	return func(g *trivyTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new trivy transformer.
func New(opts ...TrivyTransformerOption) (*trivyTransformer, error) {
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

	t := trivyTransformer{
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
func (g *trivyTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw trivy output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
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

	transformer, err := sarif.NewTransformer(&report, "", g.clock, guidProvider, true)
	if err != nil {
		return nil, err
	}
	ocsfVulns, err := transformer.ToOCSF(ctx, component.TargetMetadataFromCtx(ctx))
	if err != nil {
		return nil, err
	}
	return g.PostProcessing(ctx, ocsfVulns)
}

func (g *trivyTransformer) PostProcessing(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		if vuln.FindingInfo == nil {
			return nil, errors.Errorf("nil findingInfo for finding: %#v", vuln)
		}
		var datasource ocsffindinginfo.DataSource
		protojson.Unmarshal([]byte(vuln.FindingInfo.DataSources[0]), &datasource)
		purl := datasource.OciPackageMetadata.PackageUrl
		for _, v := range vuln.Vulnerabilities {
			if len(v.AffectedPackages) == 0 {
				v.AffectedPackages = append(v.AffectedPackages, &ocsf.AffectedPackage{
					Purl: &purl,
				})
			}
		}
	}
	return vulns, nil
}
