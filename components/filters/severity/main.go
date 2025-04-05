package main

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	v1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type SeverityFilter struct{}

func (s SeverityFilter) Filter(ctx context.Context, findings []*vf.VulnerabilityFinding) ([]*vf.VulnerabilityFinding, bool, error) {
	component.LoggerFromContext(ctx).Info("Running Severity Filter")
	findings_filtered := 0
	for _, f := range findings {
		switch f.Finding.SeverityId {
		case v1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN:
		case v1.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL:
		case v1.VulnerabilityFinding_SEVERITY_ID_LOW:
		case v1.VulnerabilityFinding_SEVERITY_ID_MEDIUM:
			f.Finding.Enrichments = append(f.Finding.Enrichments, &v1.Enrichment{})
			findings_filtered++
		}
	}
	component.LoggerFromContext(ctx).Info("filtered", slog.Int("findings_filtered", findings_filtered))
	return findings, findings_filtered > 0, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunFilter(ctx, SeverityFilter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
