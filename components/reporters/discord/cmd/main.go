package main

import (
	"context"
	"log"
	"time"

	_ "github.com/bwmarrin/discordgo"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/reporters/discord/internal/config"
	"github.com/smithy-security/smithy/components/reporters/discord/internal/discord"
	"github.com/smithy-security/smithy/components/reporters/discord/internal/reporter"
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
		return errors.Errorf("failed to get config: %w", err)
	}

	cfg.Discord.BaseClient, err = retry.NewClient(
		retry.Config{
			Logger: componentlogger.LoggerFromContext(ctx),
		},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	dc, err := discord.NewClient(cfg.Discord)
	if err != nil {
		return errors.Errorf("failed to create discord client: %w", err)
	}

	r, err := reporter.New(cfg, dc)
	if err != nil {
		return errors.Errorf("failed to create reporter: %w", err)
	}

	if err := component.RunReporter(
		ctx,
		r,
		component.RunnerWithComponentName("discord"),
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
