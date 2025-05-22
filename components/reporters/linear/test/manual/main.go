package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/config"
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
	logger := component.LoggerFromContext(ctx)

	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("failed to get config: %w", err)
	}

	rt, err := client.NewAuthRoundTripper(cfg.Linear.APIKey)
	if err != nil {
		return errors.Errorf("failed to create round tripper: %w", err)
	}

	cfg.Linear.Client, err = retry.NewClient(
		retry.Config{
			BaseTransport: rt,
			Logger:        logger,
		},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	lc, err := client.New(ctx, cfg.Linear)
	if err != nil {
		return errors.Errorf("failed to create linear client: %w", err)
	}

	r, err := reporter.New(cfg, lc)
	if err != nil {
		return errors.Errorf("failed to create reporter client: %w", err)
	}

	return r.Report(ctx, []*vf.VulnerabilityFinding{
		{
			ID: 1,
			Finding: &ocsf.VulnerabilityFinding{
				FindingInfo: &ocsf.FindingInfo{
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"util/middleware/middleware.go\"}, \"fileFindingLocationData\":{\"startLine\":70, \"endLine\":76, \"startColumn\":4, \"endColumn\":4}, \"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\", \"reference\":\"master\"}}",
					},
				},
				Confidence: utils.Ptr("High"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Title: utils.Ptr("New vulnerability 1"),
						Desc:  utils.Ptr("Fix fix fix"),
						AffectedCode: []*ocsf.AffectedCode{
							{
								EndLine: utils.Ptr(int32(12)),
								File: &ocsf.File{
									Path: utils.Ptr("file://hack-me/main.go"),
								},
								StartLine: utils.Ptr(int32(10)),
							},
						},
						Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
						VendorName: utils.Ptr("gosec"),
						Cve: &ocsf.Cve{
							Desc:  utils.Ptr("Super bad"),
							Title: utils.Ptr("CVE-1"),
						},
						Cwe: &ocsf.Cwe{
							Caption: utils.Ptr("CWE-1"),
							SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/843.html"),
						},
					},
				},
			},
		},
	})
}
