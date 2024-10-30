package component

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

type (
	// runner is used to setup the run context.
	runner struct {
		config *RunnerConfig
	}

	// componentRunnerFunc is an alias for executing component run functions.
	componentRunnerFunc func(context.Context, *RunnerConfig) error
)

// newRunner returns a new runner which is initialised looking at the default configuration
// and can be customised applying options.
// Returns an error if the configuration is invalid.
func newRunner(opts ...RunnerOption) (*runner, error) {
	cfg, err := newRunnerConfig()
	if err != nil {
		return nil, fmt.Errorf("could not create default runner configuration: %w", err)
	}

	r := &runner{config: cfg}

	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}

	if err := r.config.isValid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return r, nil
}

// run is the core of the component SDK.
// run performs all the steps needed to run components reliably and predictably.
// run takes care of:
// - signal termination: gracefully close components when a termination signal is detected.
// - context cancellation: gracefully close components when a cancellation is detected.
// - panic handling.
// - logging: initialisation and centralisation.
// - running components: reliably and respecting cancellations.
// - TODO: metrics.
// - TODO: tracing.
func run(
	ctx context.Context,
	componentRunner componentRunnerFunc,
	opts ...RunnerOption,
) error {
	r, err := newRunner(opts...)
	if err != nil {
		return fmt.Errorf("could not create runner: %w", err)
	}

	var (
		conf   = r.config
		logger = r.
			config.Logging.Logger.
			With(logKeySDKVersion, conf.SDKVersion).
			With(logKeyWorkflowID, conf.WorkflowID.String()).
			With(logKeyComponentName, conf.ComponentName)
		syncErrs = make(chan error, 1)
	)

	ctx, cancel := signal.NotifyContext(
		ContextWithLogger(ctx, logger),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGABRT,
		syscall.SIGKILL,
	)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// shutdown the application in case of:
	// - cancellations
	// - components being done with their work
	g.Go(func() error {
		select {
		case <-ctx.Done():
			logger.Debug("received a context cancellation, exiting...")
		case err := <-syncErrs:
			logger.Debug("received an unexpected error, exiting...")
			return err
		}

		return nil
	})

	// Run the component and forward errors if detected or simply tell to shut down the app when done.
	g.Go(func() error {
		// We know that we won't have more errors being sent so we can close this safely.
		defer close(syncErrs)

		// Handle main loop panics.
		defer func() {
			if pe := recover(); pe != nil {
				logger.Error("received an unexpected panic in the component runner, handling...")
				if panicErr, ok := r.config.PanicHandler.HandlePanic(ctx, pe); ok {
					logger.Error("shutting application down...")
					syncErrs <- fmt.Errorf("unexpected panic error in the component runner: %w", panicErr)
				}
				logger.Error("panic handled in the component runner!")
			}
		}()

		logger.Debug("running component...")
		// TODO: potentially decompose run steps to handle cancellations separately.
		// Actually run the component.
		if err := componentRunner(ctx, conf); err != nil {
			return fmt.Errorf("could not run component: %w", err)
		}

		logger.Debug("component done! Preparing to exit...")
		// We're done, telling the runner to exit.
		cancel()
		return nil
	})

	// Wait for all the runner bits to be done and report an error if fatal and unexpected.
	if err := g.Wait(); err != nil && !isContextErr(err) {
		return fmt.Errorf("unexpected run error: %w", err)
	}

	return nil
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
