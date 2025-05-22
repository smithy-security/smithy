package main

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/config"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear/client"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	logger := component.LoggerFromContext(ctx)
	logger.Info("preparing to retrieve teams' info...")

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

	teams, err := lc.GetTeams(ctx)
	if err != nil {
		return errors.Errorf("failed to get teams: %w", err)
	}

	logger.Info(
		"retrieved teams info!",
		slog.Any("teams", teams),
	)

	return nil
}
