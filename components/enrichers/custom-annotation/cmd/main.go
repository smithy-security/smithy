package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/enrichers/custom-annotation/internal/annotation"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("custom-annotation"))

	cfg, err := annotation.NewConf()
	if err != nil {
		return errors.Errorf("error reading annotation config: %w", err)
	}

	annotator, err := annotation.NewCustomAnnotator(cfg)
	if err != nil {
		return errors.Errorf("error creating custom annotation annotator: %w", err)
	}

	if err := component.RunEnricher(ctx, annotator, opts...); err != nil {
		return errors.Errorf("error enriching custom annotation: %w", err)
	}

	return nil
}
