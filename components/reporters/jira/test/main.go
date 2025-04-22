package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

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

	jiraIssuerCreator, err := jira.NewClient(cfg.Jira)
	if err != nil {
		return errors.Errorf("failed to create jira issuer creator: %w", err)
	}

	r, err := reporter.New(jiraIssuerCreator)
	if err != nil {
		return errors.Errorf("failed to create reporter: %w", err)
	}

	if err := r.Report(
		ctx,
		[]*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					Vulnerabilities: []*ocsf.Vulnerability{
						{
							Title: ptr("Miao miao"),
							Desc:  ptr("Fix fix fix"),
							AffectedCode: []*ocsf.AffectedCode{
								{
									EndLine: ptr(int32(12)),
									File: &ocsf.File{
										Path: ptr("file://hack-me/main.go"),
									},
									StartLine: ptr(int32(10)),
								},
							},
							Severity:   ptr("DANGER"),
							VendorName: ptr("gosec"),
						},
					},
				},
			},
		},
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}

func ptr[T comparable](v T) *T {
	return &v
}
