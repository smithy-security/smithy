package component

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	_ "go.uber.org/automaxprocs"
	"golang.org/x/sync/errgroup"
)

type (
	// runner is used to setup the run context.
	runner struct {
		config *RunnerConfig
	}

	// componentRunnerFunc is an alias for executing component run functions.
	componentRunnerFunc func(context.Context) error
	// closerFunc is an alias for Close methods in components.
	closerFunc func(ctx context.Context) error
)

// newRunner returns a new runner which is initialised looking at the default configuration
// and can be customised applying options.
func newRunner(opts ...RunnerOption) (*runner, error) {
	cfg, err := newDefaultRunnerConfig()
	if err != nil {
		return nil, fmt.Errorf("could not create default runner configuration: %w", err)
	}

	r := &runner{config: cfg}

	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// run is the core of the component SDK.
// run performs all the steps needed to run components reliably and predictably.
// run takes care of:
// - signal termination: gracefully close components when a termination signal is detected.
// - context cancellation: gracefully close components when a cancellation is detected.
// - automatically setting GOMAXPROCS: Automatically set GOMAXPROCS to match Linux container CPU quota - https://github.com/uber-go/automaxprocs.
// - panic handling.
// - logging: initialisation and centralisation.
// - running components: reliably and respecting cancellations.
// - closing components: gracefully closing components to avoid inconsistencies.
// - TODO: metrics.
// - TODO: profiling.
// - TODO: tracing.
func run(
	ctx context.Context,
	componentRunner componentRunnerFunc,
	closer closerFunc,
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
			With(logKeyComponentName, conf.ComponentName)
		syncClose = make(chan struct{}, 1)
		syncDone  = make(chan struct{}, 1)
		syncErrs  = make(chan error, 1)
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
	// - fatal errors
	g.Go(func() error {
		var e error
		select {
		case <-ctx.Done():
			logger.Debug("received a context cancellation, exiting...")
		case <-syncDone:
			logger.Debug("component done, exiting...")
		case err := <-syncErrs:
			logger.Debug("received an unexpected error, exiting...")
			e = err
		}

		syncClose <- struct{}{}
		close(syncClose)

		return e
	})

	// Make sure we wait for errors or the channel being closed so we can report them safely.
	g.Go(func() error {
		return <-syncErrs
	})

	// Gracefully close components when we're done.
	g.Go(func() error {
		<-syncClose
		logger.Debug("gracefully shutting down component...")
		closeCtx, closeCanc := context.WithTimeout(ctx, 10*time.Second)
		defer closeCanc()

		// Just in case the provided Close implementation fails.
		defer func() {
			if pe := recover(); pe != nil {
				logger.Error("received an unexpected panic during closing the component, handling...")
				var logFields []slog.Attr
				err, ok := r.config.PanicHandler.HandlePanic(ctx, pe)
				if ok {
					if err != nil {
						logFields = append(logFields, slog.String(logKeyError, err.Error()))
					}
				}
				logger.Error("panic handled during closing the component!", logFields)
			}
		}()

		// Actually close the component.
		if err := closer(closeCtx); err != nil {
			logger.Warn(
				"could not gracefully close component",
				slog.String(logKeyError, err.Error()),
			)
		}

		logger.Debug("gracefully shutdown component successfully!")
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
				var logFields []slog.Attr
				err, ok := r.config.PanicHandler.HandlePanic(ctx, pe)
				if ok {
					if err != nil {
						logFields = append(logFields, slog.String(logKeyError, err.Error()))
					}
					logger.Error("shutting application down...", logFields)
					syncErrs <- fmt.Errorf("unexpected panic error in the component runner: %w", err)
				}
				logger.Error("panic handled in the component runner!", logFields)
			}
		}()

		logger.Debug("running component...")
		// TODO: potentially decompose run steps to handle cancellations separately.
		// Actually run the component.
		if err := componentRunner(ctx); err != nil {
			syncErrs <- fmt.Errorf("could not run component: %w", err)
			return nil
		}

		logger.Debug("component done! Preparing to exit...")
		// We're done, telling the runner to exit.
		syncDone <- struct{}{}
		close(syncDone)
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
