package component

import (
	"context"

	"github.com/go-errors/errors"
)

// RunFilter runs a filter after initialising the run context.
func RunFilter(ctx context.Context, filter Filter, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				instanceID = cfg.InstanceID
				logger     = LoggerFromContext(ctx).With(logKeyComponentType, "filter")
				store      = cfg.Storer
			)

			defer func() {
				if err := store.Close(ctx); err != nil {
					logger.With(logKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute filter component...")
			logger.Debug("preparing to execute read step...")

			findings, err := store.Read(ctx, instanceID)
			if err != nil {
				logger.With(logKeyError, err.Error()).Error("reading step failed")
				return errors.Errorf("could not read: %w", err)
			}

			logger = logger.With(logKeyNumParsedFindings, len(findings))
			logger.Debug("read step completed!")

			logger.Debug("preparing to execute filter step...")
			filteredFindings, ok, err := filter.Filter(ctx, findings)
			switch {
			case err != nil:
				logger.With(logKeyError, err.Error()).Error("filter step failed")
				return errors.Errorf("could not filter: %w", err)
			case !ok:
				logger.Debug("no findings were filtered, returning")
				return nil
			}

			logger = logger.With(logKeyNumFilteredFindings, len(filteredFindings))
			logger.Debug("filter step completed!")
			logger.Debug("preparing to execute update step...")

			if err := store.Update(ctx, instanceID, filteredFindings); err != nil {
				logger.With(logKeyError, err.Error()).Error("updating step failed")
				return errors.Errorf("could not update: %w", err)
			}

			logger.Debug("updated step completed!")
			logger.Debug("filter component has completed successfully!")

			return nil
		},
		opts...,
	)
}
