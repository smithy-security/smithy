package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/new-components/reporters/json-logger/internal/reporter"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("json-logger"))

	if err := component.RunReporter(
		ctx,
		reporter.NewJsonLogger(),
		opts...,
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
