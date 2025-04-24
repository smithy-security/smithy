package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	v1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

var providerName = "severity-filter"

type SeverityFilter struct {
	minimumSeverity v1.VulnerabilityFinding_SeverityId
}

func NewSeverityFilter() (*SeverityFilter, error) {
	severityStr := os.Getenv("MINIMUM_SEVERITY")
	if severityStr == "" {
		severityStr = "MEDIUM" // Default to MEDIUM if not specified
	}
	severityStr = strings.ToUpper(severityStr)
	severityId, ok := v1.VulnerabilityFinding_SeverityId_value["SEVERITY_ID_"+severityStr]
	if !ok {
		return nil, fmt.Errorf("invalid MINIMUM_SEVERITY value: %s. Must be one of: UNKNOWN, INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL", severityStr)
	}

	return &SeverityFilter{
		minimumSeverity: v1.VulnerabilityFinding_SeverityId(severityId),
	}, nil
}

func (s SeverityFilter) Filter(ctx context.Context, findings []*vf.VulnerabilityFinding) ([]*vf.VulnerabilityFinding, bool, error) {
	component.LoggerFromContext(ctx).Info("Running Severity Filter")
	findings_filtered := 0
	for _, f := range findings {
		if f.Finding.SeverityId >= s.minimumSeverity {
			enrichment := ocsffindinginfo.Enrichment{
				EnrichmentType: ocsffindinginfo.Enrichment_ENRICHMENT_FILTER,
				Enrichment:     &ocsffindinginfo.Enrichment_Filter{},
			}
			toBytes, err := protojson.Marshal(&enrichment)
			if err != nil {
				return nil, false, fmt.Errorf("failed to marshal enrichment %v err: %w", enrichment, err)
			}
			f.Finding.Enrichments = append(f.Finding.Enrichments, &v1.Enrichment{
				Name:     providerName,
				Provider: &providerName,
				Value:    string(toBytes),
			})
			findings_filtered++
		}
	}
	component.LoggerFromContext(ctx).Info("filtered", slog.Int("findings_filtered", findings_filtered))
	return findings, findings_filtered > 0, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	filter, err := NewSeverityFilter()
	if err != nil {
		log.Fatalf("failed to create severity filter: %v", err)
	}

	if err := component.RunFilter(ctx, *filter, component.RunnerWithComponentName("Severity Filter")); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
