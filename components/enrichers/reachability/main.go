package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom/purl"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/conf"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/enricher"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/fs"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/logging"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGABRT,
		syscall.SIGINT,
		syscall.SIGKILL,
	)

	defer cancel()

	logger := logging.NewLogger()
	ctx = logging.WithContext(ctx, logger)

	if err := Main(ctx, cancel); err != nil {
		logger.Error("unexpected error", slog.String("err", err.Error()))
	}
}

func Main(ctx context.Context, cancel func()) error {
	cfg, err := conf.New()
	if err != nil {
		return fmt.Errorf("could not load configuration: %w", err)
	}

	purlParser, err := purl.NewParser()
	if err != nil {
		return fmt.Errorf("could not initialize purl parser: %w", err)
	}

	atomReader, err := atom.NewReader(cfg.ATOMFilePath, purlParser)
	if err != nil {
		return fmt.Errorf("could not initialize atom reader: %w", err)
	}

	fsReadWriter, err := fs.NewReadWriter(cfg.ProducerResultsPath, cfg.EnrichedResultsPath)
	if err != nil {
		return fmt.Errorf("could not initialize filesystem read/writer: %w", err)
	}

	enr, err := enricher.NewEnricher(cfg, atomReader, fsReadWriter)
	if err != nil {
		return fmt.Errorf("could not initialize enricher: %w", err)
	}

	g, egCtx := errgroup.WithContext(ctx)

	// Terminates earlier if the context is cancelled.
	g.Go(func() error {
		<-egCtx.Done()
		return egCtx.Err()
	})

	g.Go(func() error {
		if err := enr.Enrich(egCtx); err != nil {
			return fmt.Errorf("unexpected error while enriching: %w", err)
		}
		cancel()
		return nil
	})

	if err := g.Wait(); err != nil && !isCtxErr(err) {
		return fmt.Errorf("unexpected error in waitgroup: %w", err)
	}

	return nil
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
