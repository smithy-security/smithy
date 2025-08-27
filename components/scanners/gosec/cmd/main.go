package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/scanners/gosec/internal/config"
	"github.com/smithy-security/smithy/components/scanners/gosec/internal/transformer"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("failed to initialize config: %w", err)
	}

	ocsfTransformer, err := transformer.New(cfg)
	if err != nil {
		return errors.Errorf("could not create transformer: %w", err)
	}

	if err := component.RunScanner(
		ctx,
		ocsfTransformer,
		component.RunnerWithComponentName("gosec"),
	); err != nil {
		return errors.Errorf("could not run scanner: %w", err)
	}

	return nil
}
