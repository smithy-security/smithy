package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter"
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
	c := http.Client{}
	slackLogger, err := reporter.NewSlackLogger(config, &c)
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
