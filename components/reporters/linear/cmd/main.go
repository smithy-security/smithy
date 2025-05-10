package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"

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
	conf, err := reporter.NewConf()
	if err != nil {
		return errors.Errorf("could not get config: %w", err)
	}

	authTrans, err := client.NewAuthRoundTripper(conf.LinearAPIKey)
	if err != nil {
		return errors.Errorf("could not create auth round tripper: %v", err)
	}

	retryClient, err := retry.NewClient(
		retry.Config{
			BaseTransport: authTrans,
			Logger:        component.LoggerFromContext(ctx),
		},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	lc, err := client.New(client.Config{
		Client:  retryClient,
		BaseURL: conf.LinearBaseURL,
	})

	r, err := reporter.New(lc)
	if err != nil {
		return errors.Errorf("failed to create reporter: %w", err)
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
