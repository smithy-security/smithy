package transformer

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	"github.com/go-errors/errors"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/modules"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/transformer"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/wrapper"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
)

type (
	OSVScannerTransformer struct {
		cfg config.Config
	}
)

// New returns a new credo transformer.
func New(cfg config.Config) (OSVScannerTransformer, error) {
	return OSVScannerTransformer{
		cfg: cfg,
	}, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (o OSVScannerTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)
	logger.Debug(
		"preparing to invoke OSV scanner for the repository...",
		slog.String("repo_root", o.cfg.Root),
	)

	// Find all the code modules
	moduleFinder, err := modules.NewFinder(ctx, o.cfg)
	if err != nil {
		return nil, errors.Errorf("could not initialise module finder: %w", err)
	}

	modules, err := moduleFinder.Find(ctx)
	if err != nil {
		return nil, errors.Errorf("could not scan for modules: %w", err)
	} else if len(modules) == 0 {
		logger.Info("no modified or supported modules found")
		return nil, nil
	}

	// Run the OSV scanner
	osvSCA, err := wrapper.NewOSVSourceScanner(slices.Collect(maps.Keys(modules)))
	if err != nil {
		return nil, errors.Errorf("could not bootstrap OSV scanner: %w", err)
	}

	vulns, err := osvSCA.Scan(ctx)
	if err != nil {
		return nil, errors.Errorf("could not perform scan: %w", err)
	}

	ocsfTransformer, err := transformer.New(o.cfg)
	if err != nil {
		return nil, errors.Errorf("could not create transformer: %w", err)
	}

	return ocsfTransformer.Transform(ctx, vulns)
}
