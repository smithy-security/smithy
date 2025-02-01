package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/new-components/reporters/slack/internal/reporter"
	"github.com/smithy-security/smithy/sdk/component"
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
		return err
	}
	slackLogger, err := reporter.NewSlackLogger(config)
	if err != nil {
		return err
	}
	if err := component.RunReporter(
		ctx,
		slackLogger,
		opts...,
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
