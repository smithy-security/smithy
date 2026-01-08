package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"

	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter"
	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter/slack"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("slack"))
	config, err := reporter.NewConf(nil)
	if err != nil {
		return errors.Errorf("failed to get config: %w", err)
	}

	config.SlackClientConfig.BaseClient, err = retry.NewClient(
		retry.Config{
			Logger: componentlogger.LoggerFromContext(ctx),
		},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	sl, err := slack.NewClient(ctx, config.SlackClientConfig)
	if err != nil {
		return errors.Errorf("failed to create slack client: %w", err)
	}
	slackReporter, err := reporter.NewSlackReporter(config, sl)
	if err != nil {
		return errors.Errorf("failed to create slack reporter: %w", err)
	}

	if err := component.RunReporter(
		ctx,
		slackReporter,
		opts...,
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
