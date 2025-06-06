package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/elasticsearch/internal/reporter"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	conf, err := reporter.NewConf(nil)
	if err != nil {
		return errors.Errorf("could not create new configuration: %w", err)
	}
	opts = append(opts, component.RunnerWithComponentName("elasticsearch"))

	client, err := reporter.GetESClient(conf)
	if err != nil {
		return errors.Errorf("could not create elasticsearch client: %w", err)
	}

	reporter, err := reporter.NewElasticsearchLogger(conf, client)
	if err != nil {
		return errors.Errorf("could not instantiate logger err: %w", err)
	}
	if err := component.RunReporter(ctx, reporter, opts...); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
