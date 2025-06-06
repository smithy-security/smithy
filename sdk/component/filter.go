package component

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/store"
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
)

// RunFilter runs a filter after initialising the run context.
func RunFilter(ctx context.Context, filter Filter, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				instanceID = cfg.InstanceID
				logger     = sdklogger.LoggerFromContext(ctx).With(sdklogger.LogKeyComponentType, "filter")
				storer     = cfg.StoreConfig.Storer
			)

			defer func() {
				if err := storer.Close(ctx); err != nil {
					logger.With(sdklogger.LogKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute filter component...")
			logger.Debug("preparing to execute read step...")

			findings, err := storer.Read(ctx, instanceID)
			if err != nil {
				if errors.Is(err, store.ErrNoFindingsFound) {
					logger.Debug("no findings found, skipping filter step...")
					return nil
				}
				logger.With(sdklogger.LogKeyError, err.Error()).Error("reading step failed")
				return errors.Errorf("could not read: %w", err)
			}

			if len(findings) == 0 {
				logger.Debug("no findings found, skipping filter step...")
				return nil
			}

			logger = logger.With(sdklogger.LogKeyNumParsedFindings, len(findings))
			logger.Debug("read step completed!")

			logger.Debug("preparing to execute filter step...")
			filteredFindings, ok, err := filter.Filter(ctx, findings)
			switch {
			case err != nil:
				logger.With(sdklogger.LogKeyError, err.Error()).Error("filter step failed")
				return errors.Errorf("could not filter: %w", err)
			case !ok:
				logger.Debug("no findings were filtered, returning")
				return nil
			}

			logger = logger.With(sdklogger.LogKeyNumFilteredFindings, len(filteredFindings))
			logger.Debug("filter step completed!")
			logger.Debug("preparing to execute update step...")

			if err := storer.Update(ctx, instanceID, filteredFindings); err != nil {
				logger.With(sdklogger.LogKeyError, err.Error()).Error("updating step failed")
				return errors.Errorf("could not update: %w", err)
			}

			logger.Debug("updated step completed!")
			logger.Debug("filter component has completed successfully!")

			return nil
		},
		opts...,
	)
}
