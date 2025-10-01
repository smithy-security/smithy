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
	// SobelowTransformerOption allows customising the transformer.
	SobelowTransformerOption func(g *sobelowTransformer) error

	// TargetType represents the target type.
	TargetType string

	sobelowTransformer struct {
		targetType     TargetType
		clock          clockwork.Clock
		resultsDirPath string
		workspacePath  string
	}
)

func (tt TargetType) String() string {
	return string(tt)
}

// SobelowTransformerWithClock allows customising the underlying clock.
func SobelowTransformerWithClock(clock clockwork.Clock) SobelowTransformerOption {
	return func(g *sobelowTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// SobelowTransformerWithTarget allows customising the underlying target type.
func SobelowTransformerWithTarget(target TargetType) SobelowTransformerOption {
	return func(g *sobelowTransformer) error {
		if target == "" {
			return errors.Errorf("invalid empty target")
		}
		g.targetType = target
		return nil
	}
}

func SobelowResultsDirPath(path string) SobelowTransformerOption {
	return func(g *sobelowTransformer) error {
		if path == "" {
			return errors.Errorf("invalid results dir path")
		}
		g.resultsDirPath = path
		return nil
	}
}

// New returns a new sobelow transformer.
func New(opts ...SobelowTransformerOption) (*sobelowTransformer, error) {
	resultsDirPath, err := env.GetOrDefault(
		"SOBELOW_RESULTS_DIR",
		"/results",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	target, err := env.GetOrDefault(
		"SOBELOW_TARGET_TYPE",
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

	t := sobelowTransformer{
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
func (g *sobelowTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("preparing to scan and merge SARIF files from directory...",
		slog.String("directory", g.resultsDirPath),
	)

	// Read all files from the results directory.
	files, err := os.ReadDir(g.resultsDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("results directory '%s' not found", g.resultsDirPath)
		}
		return nil, errors.Errorf("failed to read results directory '%s': %w", g.resultsDirPath, err)
	}

	var masterReport *sarifschemav210.SchemaJson

	// Iterate over each file, parse it, and merge its results.
	for _, file := range files {
		// Skip directories and files that are not SARIF reports.
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sarif.json") {
			continue
		}

		filePath := filepath.Join(g.resultsDirPath, file.Name())
		logger.Debug("processing SARIF file",
			slog.String("file", filePath),
		)

		b, err := os.ReadFile(filePath)
		if err != nil {
			// Log error for the specific file but continue processing others.
			logger.Error("failed to read SARIF file, skipping",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			continue
		}

		if len(b) == 0 {
			logger.Debug("SARIF file is empty, skipping", slog.String("file", filePath))
			continue
		}

		var currentReport sarifschemav210.SchemaJson
		if err := currentReport.UnmarshalJSON(b); err != nil {
			logger.Error("failed to parse SARIF file, skipping",
				slog.String("file", filePath),
				slog.String("error", err.Error()),
			)
			continue
		}

		// If this is the first valid report, use it as the base.
		if masterReport == nil {
			masterReport = &currentReport
			// Ensure there's at least one run to append to.
			if len(masterReport.Runs) == 0 {
				logger.Error("initial SARIF report has no runs, cannot merge",
					slog.String("file", filePath),
				)
				masterReport = nil
				continue
			}
		} else {
			// Merge the results from the current report into the master report.
			for _, run := range currentReport.Runs {
				if len(masterReport.Runs) > 0 {
					masterReport.Runs[0].Results = append(masterReport.Runs[0].Results, run.Results...)
				}
			}
		}
	}

	// Check if any findings were found after iterating through all files.
	if masterReport == nil {
		logger.Debug("no valid SARIF reports with findings were found in the directory")
		return []*ocsf.VulnerabilityFinding{}, nil
	}

	logger.Debug(
		"successfully merged all SARIF reports!",
		slog.Int("num_sarif_runs", len(masterReport.Runs)),
		slog.Int("num_sarif_results", func(runs []sarifschemav210.Run) int {
			var countRes = 0
			for _, run := range runs {
				countRes += len(run.Results)
			}
			return countRes
		}(masterReport.Runs)),
	)

	logger.Debug("preparing to parse raw sarif findings to ocsf vulnerability findings...")
	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to create guid provider: %w", err)
	}

	transformer, err := sarif.NewTransformer(
		masterReport,
		"",
		g.clock,
		guidProvider,
		true,
		component.TargetMetadataFromCtx(ctx),
		g.workspacePath,
	)
	if err != nil {
		return nil, err
	}

	return transformer.ToOCSF(ctx)
}
