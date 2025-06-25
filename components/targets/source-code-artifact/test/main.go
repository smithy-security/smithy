package main

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/go-errors/errors"
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

func Main(ctx context.Context) error {
	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("could not initialize config: %w", err)
	}

	l := logger.LoggerFromContext(ctx)
	l.Debug("configuring extractor...")
	extractor, fileType, err := target.GetExtractor(cfg.Fetcher.ArtifactURL)
	if err != nil {
		return errors.Errorf("could not get extractor: %w", err)
	}
	l = l.With(slog.String("file_type", fileType.String()))
	l.Debug("successfully configured extractor!")

	l.Debug("configuring source code artifact fetcher...")
	f, sourceType, err := target.GetFetcher(ctx, cfg.Fetcher)
	if err != nil {
		return errors.Errorf("could not get fetcher: %w", err)
	}
	l = l.With(slog.String("source_type", sourceType.String()))
	l.Debug("successfully configured source code artifact fetcher!")

	t, err := target.New(cfg.Target, f, persister.New(), extractor, metadata.NewWriter(cfg.Metadata))
	if err != nil {
		return errors.Errorf("could not initialize target: %w", err)
	}

	return t.Prepare(ctx)
}
