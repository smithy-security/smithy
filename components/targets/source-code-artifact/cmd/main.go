package main

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/persister"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/config"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/metadata"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/target"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

// Main is the entrypoint to the source code artefact fetcher
func Main(ctx context.Context) error {
	l := logger.LoggerFromContext(ctx)

	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("could not initialize config: %w", err)
	}

	l.Debug("configuring extractor...")
	extractor, fileType, err := target.GetExtractor(cfg.Metadata.FileType)
	if err != nil {
		return errors.Errorf("could not get extractor: %w", err)
	}
	l = l.With(slog.String("file_type", fileType.String()))
	l.Debug("successfully configured extractor!")

	l.Debug("configuring source code artifact fetcher...")
	fetcher, sourceType, err := target.GetFetcher(ctx, cfg.Fetcher)
	if err != nil {
		return errors.Errorf("could not get fetcher: %w", err)
	}
	l = l.With(slog.String("source_type", sourceType.String()))
	l.Debug("successfully configured source code artifact fetcher!")

	t, err := target.New(
		cfg.Target,
		fetcher,
		persister.New(),
		extractor,
		metadata.NewWriter(cfg.Metadata),
	)
	if err != nil {
		return errors.Errorf("could not initialize target: %w", err)
	}

	if err := component.RunTarget(
		logger.ContextWithLogger(ctx, l),
		t,
		component.RunnerWithComponentName("source-code-artifact"),
	); err != nil {
		return errors.Errorf("could not run target: %w", err)
	}

	return nil
}
