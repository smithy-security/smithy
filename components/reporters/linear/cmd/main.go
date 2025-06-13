package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/config"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear/client"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/reporter"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	logger := componentlogger.LoggerFromContext(ctx)

	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("failed to get config: %w", err)
	}

	rt, err := client.NewAuthRoundTripper(cfg.Linear.APIKey)
	if err != nil {
		return errors.Errorf("failed to create round tripper: %w", err)
	}

	cfg.Linear.Client, err = retry.NewClient(
		retry.Config{
			BaseTransport: rt,
			Logger:        logger,
		},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	lc, err := client.New(ctx, cfg.Linear)
	if err != nil {
		return errors.Errorf("failed to create linear client: %w", err)
	}

	r, err := reporter.New(cfg, lc)
	if err != nil {
		return errors.Errorf("failed to create reporter client: %w", err)
	}

	if err := component.RunReporter(
		ctx,
		r,
		component.RunnerWithComponentName("linear"),
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
