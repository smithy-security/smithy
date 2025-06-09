package component

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/store"
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
)

// RunReporter runs a reporter after initialising the run context.
func RunReporter(ctx context.Context, reporter Reporter, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				instanceID = cfg.InstanceID
				logger     = sdklogger.LoggerFromContext(ctx).With(sdklogger.LogKeyComponentType, "reporter")
				storer     = cfg.StoreConfig.Storer
			)

			defer func() {
				if err := storer.Close(ctx); err != nil {
					logger.With(sdklogger.LogKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute component...")
			logger.Debug("preparing to execute read step...")

			findings, err := storer.Read(ctx, instanceID)
			if err != nil {
				if errors.Is(err, store.ErrNoFindingsFound) {
					logger.Debug("no findings found, skipping reporter step...")
					return nil
				}
				logger.With(sdklogger.LogKeyError, err.Error()).Error("reading step failed")
				return errors.Errorf("could not read: %w", err)
			}

			if len(findings) == 0 {
				logger.Debug("no findings found, skipping reporter step...")
				return nil
			}

			logger.Debug("read step completed!")
			logger.Debug("preparing to execute report step...")

			if err := reporter.Report(ctx, findings); err != nil {
				logger.
					With(sdklogger.LogKeyError, err.Error()).
					Debug("could not execute report step")
				return errors.Errorf("could not report findings: %w", err)
			}

			logger.Debug("reporter step completed!")
			logger.Debug("component has completed successfully!")

			return nil
		},
		opts...,
	)
}
