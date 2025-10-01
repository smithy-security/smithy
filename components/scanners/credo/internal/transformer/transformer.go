package transformer

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
	// CredoTransformerOption allows customising the transformer.
	CredoTransformerOption func(g *credoTransformer) error

	// TargetType represents the target type.
	TargetType string

	credoTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		resultsDirPath string
		workspacePath  string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// CredoTransformerWithClock allows customising the underlying clock.
func CredoTransformerWithClock(clock clockwork.Clock) CredoTransformerOption {
	return func(g *credoTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// CredoTransformerWithTarget allows customising the underlying target type.
func CredoTransformerWithTarget(target TargetType) CredoTransformerOption {
	return func(g *credoTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

// CredoResultsDirPath allows customising the results directory path
func CredoResultsDirPath(path string) CredoTransformerOption {
	return func(g *credoTransformer) error {
		if path == "" {
			return errors.Errorf("invalid results directory path")
		}
		g.resultsDirPath = path
		return nil
	}
}

// New returns a new credo transformer.
func New(opts ...CredoTransformerOption) (*credoTransformer, error) {
	resultsDirPath, err := env.GetOrDefault(
		"CREDO_RESULTS_DIR",
		"/results",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"CREDO_TARGET_TYPE",
		TargetTypeRepository.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	workspacePath, err := env.GetOrDefault(
		"WORKSPACE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	t := credoTransformer{
		targetType:     TargetType(target),
		clock:          clockwork.NewRealClock(),
		resultsDirPath: resultsDirPath,
		workspacePath:  workspacePath,
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	switch {
	case t.resultsDirPath == "":
		return nil, errors.New("invalid empty results directory path")
	case t.targetType == "":
		return nil, errors.New("invalid empty target type")
	}

	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *credoTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	var (
		errs            error
		allOcsfFindings []*ocsf.VulnerabilityFinding
		logger          = componentlogger.LoggerFromContext(ctx)
	)

	logger.Debug("preparing to parse raw credo output...")

	// Read all files from the results directory.
	files, err := os.ReadDir(g.resultsDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("results directory '%s' not found", g.resultsDirPath)
		}
		return nil, errors.Errorf("failed to read results directory '%s': %w", g.resultsDirPath, err)
	}

	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to create guid provider: %w", err)
	}

	// Iterate over each file, parse it, and merge its results.
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sarif.json") {
			continue
		}

		filePath := filepath.Join(g.resultsDirPath, file.Name())
		logger.Debug("processing SARIF file",
			slog.String("file", filePath),
		)

		b, err := os.ReadFile(filePath)
		if err != nil {
			logger.Error("failed to read SARIF file, skipping...",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			errs = errors.Join(errs, errors.Errorf("failed to read SARIF file: %w", err))
			continue
		}

		// Handle a complete empty findings file, treating as no findings.
		if len(b) == 0 {
			logger.Debug("SARIF file is empty,  treating as no findings and skipping..",
				slog.String("file", filePath),
			)
			continue
		}

		var currentReport sarifschemav210.SchemaJson
		if err := currentReport.UnmarshalJSON(b); err != nil {
			logger.Error("failed to parse SARIF file, skipping...",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			errs = errors.Join(errs, errors.Errorf("failed to parse SARIF file: %w", err))
			continue
		}

		logger.Debug(
			"successfully parsed credo output for current file",
			slog.String("file", filePath),
			slog.Int("num_sarif_runs", len(currentReport.Runs)),
			slog.Int("num_sarif_results", countSarifResults(currentReport.Runs)),
		)

		transformer, err := sarif.NewTransformer(
			&currentReport,
			"",
			g.clock,
			guidProvider,
			true,
			component.TargetMetadataFromCtx(ctx),
			g.workspacePath,
		)
		if err != nil {
			logger.Error("failed to create transformer for SARIF file",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			errs = errors.Join(errs, errors.Errorf("failed to create transformer for SARIF file: %w", err))
			continue
		}

		// Transform the single report to OCSF.
		ocsfFindings, err := transformer.ToOCSF(ctx)
		if err != nil {
			logger.Error("failed to transform SARIF file to OCSF",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			errs = errors.Join(errs, errors.Errorf("failed to transform SARIF file to OCSF: %w", err))
			continue
		}

		allOcsfFindings = append(allOcsfFindings, ocsfFindings...)
	}

	logger.Debug("finished parsings credo findings",
		slog.Int("total_ocsf_findings", len(allOcsfFindings)),
	)
	return allOcsfFindings, errs

}

// countSarifResults calculates the total number of results across all runs in a single SARIF report.
func countSarifResults(runs []sarifschemav210.Run) int {
	var count int
	for _, run := range runs {
		count += len(run.Results)
	}
	return count
}
