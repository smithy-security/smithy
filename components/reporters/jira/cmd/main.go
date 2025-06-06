package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/config"
	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer/jira"
	"github.com/smithy-security/smithy/components/reporters/jira/internal/reporter"
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
		return errors.Errorf("failed to load configuration: %w", err)
	}

	jiraIssuerCreator, err := jira.NewClient(ctx, cfg.Jira)
	if err != nil {
		return errors.Errorf("failed to create jira issuer creator: %w", err)
	}

	r, err := reporter.New(
		reporter.IssueContext{
			SmithyInstanceBaseURL: cfg.Jira.SmithyDashURL,
			SmithyRunName:         cfg.Jira.SmithyInstanceName,
			SmithyRunID:           cfg.Jira.SmithyInstanceID,
		},
		jiraIssuerCreator,
	)
	if err != nil {
		return errors.Errorf("failed to create reporter: %w", err)
	}

	if err := component.RunReporter(
		ctx,
		r,
		component.RunnerWithComponentName("jira"),
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
