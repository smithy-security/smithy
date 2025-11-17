package wrapper

import (
	"context"
	"log/slog"
	"strings"

	"github.com/go-errors/errors"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

// OSV is a wrapper around the OSV scanner, that invokes the scanner for a
// specific path
type OSVScanner struct {
	lockfiles []string
}

// NewOSVSourceScanner returns a scanner that will be executed for the various
// lockfiles discovered in the repository
func NewOSVSourceScanner(lockfiles []string) (OSVScanner, error) {
	if len(lockfiles) == 0 {
		return OSVScanner{}, errors.New("no lockfiles provided")
	}

	return OSVScanner{
		lockfiles: lockfiles,
	}, nil
}

// Scan will invoke the OSV scanner for the various lockfiles registered
func (o OSVScanner) Scan(
	ctx context.Context,
) (models.VulnerabilityResults, error) {
	logger := componentlogger.LoggerFromContext(ctx)
	allLockFiles := strings.Join(o.lockfiles, ",")
	logger.Info(
		"starting OSV scan for lockfiles",
		slog.String("path", allLockFiles),
	)

	scannerAction := osvscanner.ScannerActions{
		LockfilePaths:         o.lockfiles,
		ConfigOverridePath:    "",
		ShowAllVulns:          true,
		ScanLicensesAllowlist: []string{},
		CallAnalysisStates:    map[string]bool{},
	}

	vulnResults, err := osvscanner.DoScan(scannerAction)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return models.VulnerabilityResults{},
			errors.Errorf("%s: could not scan lockfiles: %w", allLockFiles, err)
	}

	return vulnResults, nil
}
