package component

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/store"
)

// RunEnricher runs an enricher after initialising the run context.
func RunEnricher(ctx context.Context, enricher Enricher, opts ...RunnerOption) error {
	return run(
		ctx,
		func(ctx context.Context, cfg *RunnerConfig) error {
			var (
				instanceID = cfg.InstanceID
				logger     = LoggerFromContext(ctx).With(logKeyComponentType, "enricher")
				storer     = cfg.StoreConfig.Storer
			)

			defer func() {
				if err := storer.Close(ctx); err != nil {
					logger.With(logKeyError, err.Error()).Error("closing step failed, ignoring...")
				}
			}()

			logger.Debug("preparing to execute enricher component...")
			logger.Debug("preparing to execute read step...")

			findings, err := storer.Read(ctx, instanceID)
			if err != nil {
				if errors.Is(err, store.ErrNoFindingsFound) {
					logger.Debug("no findings found, skipping enrichment step...")
					return nil
				}
				logger.With(logKeyError, err.Error()).Error("reading step failed")
				return errors.Errorf("could not read: %w", err)
			}

			if len(findings) == 0 {
				logger.Debug("no findings found, skipping enrichment step...")
				return nil
			}

			logger = logger.With(logKeyNumParsedFindings, len(findings))
			logger.Debug("read step completed!")

			logger.Debug("preparing to execute enricher step...")
			enrichedFindings, err := enricher.Annotate(ctx, findings)
			if err != nil {
				logger.With(logKeyError, err.Error()).Error("enricher step failed")
				return errors.Errorf("could not enricher: %w", err)
			}

			logger = logger.With(logKeyNumEnrichedFindings, len(enrichedFindings))
			logger.Debug("enricher step completed!")
			logger.Debug("preparing to execute update step...")

			if err := storer.Update(ctx, instanceID, enrichedFindings); err != nil {
				logger.With(logKeyError, err.Error()).Error("updating step failed")
				return errors.Errorf("could not update: %w", err)
			}

			logger.Debug("updated step completed!")
			logger.Debug("enricher component has completed successfully!")

			return nil
		},
		opts...,
	)
}
