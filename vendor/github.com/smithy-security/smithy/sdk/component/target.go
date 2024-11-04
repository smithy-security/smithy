package component

import (
	"context"
	"fmt"
)

// RunTarget runs a target after initialising the run context.
func RunTarget(ctx context.Context, target Target, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			logger := LoggerFromContext(ctx).With(logKeyComponentType, "target")

			logger.Debug("preparing to execute preparation step...")

			if err := target.Prepare(ctx); err != nil {
				logger.With(logKeyError, err.Error()).Error("preparing target failed")
				return fmt.Errorf("could not prepare target: %w", err)
			}

			logger.Debug("component has completed successfully!")

			return nil
		},
		opts...,
	)
}
