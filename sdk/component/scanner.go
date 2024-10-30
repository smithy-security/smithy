package component

import (
	"context"
	"fmt"
)

// RunScanner runs a scanner after initialising the run context.
func RunScanner(ctx context.Context, scanner Scanner, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				workflowID = cfg.WorkflowID
				logger     = LoggerFromContext(ctx).With(logKeyComponentType, "scanner")
				store      = cfg.storerConfig.store
			)

			defer func() {
				if err := store.Close(ctx); err != nil {
					logger.With(logKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute component...")
			logger.Debug("preparing to execute transform step...")

			rawFindings, err := scanner.Transform(ctx)
			if err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute transform step")
				return fmt.Errorf("could not transform raw findings: %w", err)
			}

			logger = logger.
				With(logKeyNumRawFindings, len(rawFindings))
			logger.Debug("transform step completed!")
			logger.Debug("preparing to execute validate step...")

			for _, rv := range rawFindings {
				if err := store.Validate(rv); err != nil {
					logger.
						With(logKeyError, err.Error()).
						With(logKeyRawFinding, rv).
						Error("invalid raw finding")
					return fmt.Errorf("invalid raw finding: %w", err)
				}
			}

			logger.Debug("validate step completed!")
			logger.Debug("preparing to execute store step...")

			if err := store.Write(ctx, workflowID, rawFindings); err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute store step")
				return fmt.Errorf("could not store vulnerabilities: %w", err)
			}

			logger.Debug("store step completed!")
			logger.Debug("component has completed successfully!")

			return nil
		},
		opts...,
	)
}
