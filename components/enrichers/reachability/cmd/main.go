package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/annotation"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/conf"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("reachability"))

	config, err := conf.New()
	if err != nil {
		return errors.Errorf("could not initialiaze config, err: %w", err)
	}
	annotator := annotation.NewReachabilityAnnotator(config)

	if err := component.RunEnricher(ctx, annotator, opts...); err != nil {
		return errors.Errorf("error enriching reachability annotation: %w", err)
	}

	return nil
}
