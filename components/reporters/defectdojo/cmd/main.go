package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/defectdojo/internal/client"
	"github.com/smithy-security/smithy/components/reporters/defectdojo/internal/reporter"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("defectdojo"))
	config, err := reporter.NewConf(nil)
	if err != nil {
		return err
	}
	ddClient, err := client.DojoClient(ctx, config.URL, config.Token, config.User)
	if err != nil {
		return err
	}
	rep, err := reporter.New(config, ddClient)
	if err != nil {
		return err
	}
	if err := component.RunReporter(
		ctx,
		rep,
		opts...,
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}
	return nil
}
