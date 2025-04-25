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

	if err := r.Report(
		ctx,
		[]*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					FindingInfo: &ocsf.FindingInfo{
						DataSources: []string{
							"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"util/middleware/middleware.go\"}, \"fileFindingLocationData\":{\"startLine\":70, \"endLine\":76, \"startColumn\":4, \"endColumn\":4}, \"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\", \"reference\":\"master\"}}",
						},
					},
					Confidence: ptr("High"),
					Vulnerabilities: []*ocsf.Vulnerability{
						{
							Title: ptr("New vulnerability 1"),
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
							Severity:   ptr("SEVERITY_ID_MEDIUM"),
							VendorName: ptr("gosec"),
							Cve: &ocsf.Cve{
								Desc:  ptr("Super bad"),
								Title: ptr("CVE-1"),
							},
							Cwe: &ocsf.Cwe{
								Caption: ptr("CWE-1"),
								SrcUrl:  ptr("https://cwe.mitre.org/data/definitions/843.html"),
							},
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
