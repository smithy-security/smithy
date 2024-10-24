package component

import (
	"context"
	"fmt"
)

// RunReporter runs a reporter after initialising the run context.
func RunReporter(ctx context.Context, reporter Reporter, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context) error {
			logger := LoggerFromContext(ctx).With(logKeyComponentType, "reporter")

			logger.Debug("preparing to execute component...")
			logger.Debug("preparing to execute read step...")

			res, err := reporter.Read(ctx)
			if err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute read step")
				return fmt.Errorf("could not read findings: %w", err)
			}

			logger.Debug("read step completed!")
			logger.Debug("preparing to execute report step...")

			if err := reporter.Report(ctx, res); err != nil {
				logger.
					With(logKeyError, err.Error()).
					Debug("could not execute report step")
				return fmt.Errorf("could not report findings: %w", err)
			}

			logger.Debug("reporter step completed!")
			logger.Debug("component has completed successfully!")

			return nil
		},
		reporter.Close,
		opts...,
	)
}
