package component

import (
	"context"
	"fmt"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// RunScanner runs a scanner after initialising the run context.
func RunScanner(ctx context.Context, scanner Scanner, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context) error {
			logger := LoggerFromContext(ctx).With(logKeyComponentType, "scanner")

			logger.Debug("preparing to execute component...")
			logger.Debug("preparing to execute scan step...")

			rawVulns, err := scanner.Scan(ctx)
			if err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute scan step")
				return fmt.Errorf("could not scan: %w", err)
			}

			logger = logger.With(logKeyNumRawFindings, len(rawVulns))
			logger.Debug("scan step completed!")
			logger.Debug("preparing to execute transform step...")

			var vulns = make([]*ocsf.VulnerabilityFinding, 0, len(rawVulns))

			for _, rv := range rawVulns {
				parsedVuln, err := scanner.Transform(ctx, rv)
				if err != nil {
					logger.
						With(logKeyError, err.Error()).
						Debug("could not execute transform step")
					return fmt.Errorf("could not transform raw vulnerability: %w", err)
				}
				vulns = append(vulns, parsedVuln)
			}

			logger = logger.With(
				logKeyNumParsedFindings, len(vulns),
				logKeyNumFindingsMatch, len(vulns) == len(rawVulns),
			)
			logger.Debug("transform step completed!")
			logger.Debug("preparing to execute store step...")

			if err := scanner.Store(ctx, vulns); err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute store step")
				return fmt.Errorf("could not store vulnerabilities: %w", err)
			}

			logger.Debug("store step completed!")
			logger.Debug("component has completed successfully!")

			return nil
		},
		scanner.Close,
		opts...,
	)
}
