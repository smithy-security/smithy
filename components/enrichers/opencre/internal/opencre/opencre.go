package opencre

import (
	"context"
	"log/slog"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const annotationName = "OpenCREEnrichment"

type (
	creEnricher struct {
		client *OpenCREClient
	}
)

const defaultEmptyJsonObject = "{}"

// NewCREEnricher returns a new cre enricher.
func NewCREEnricher(client *OpenCREClient) (*creEnricher, error) {
	return &creEnricher{client: client}, nil
}

// Annotate adds annotated values to passed findings.
func (ca *creEnricher) Annotate(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) ([]*vf.VulnerabilityFinding, error) {
	var (
		providerName = "cre-enricher"
		logger       = component.LoggerFromContext(ctx).
				With(slog.Int("num_findings", len(findings))).
				With(slog.String("provider_name", providerName))
	)

	logger.Debug("preparing to annotate findings...")

	for idx, finding := range findings {
		for _, v := range finding.Finding.Vulnerabilities {
			if v.Cwe != nil && v.Cwe.Uid != "" {
				logger.Info("cwe uid found, annotating", slog.String("cwe_uid", v.Cwe.Uid))
				asvs := ca.client.GetASVS(v.Cwe.Uid)
				samm := ca.client.GetSAMM(v.Cwe.Uid)
				enrichments := make([]*ocsf.Enrichment, 0, 0)
				if asvs != "" {
					logger.Info("asvs found, annotating", slog.String("asvs", asvs))
					enrichments = append(enrichments, &ocsf.Enrichment{
						Name:     annotationName,
						Value:    asvs,
						Provider: &providerName,
					})
				}
				if samm != "" {
					logger.Info("samm found, annotating", slog.String("samm", samm))
					enrichments = append(enrichments, &ocsf.Enrichment{
						Name:     annotationName,
						Value:    samm,
						Provider: &providerName,
					})
				}
				if len(enrichments) > 0 {
					logger.Info("adding enrichments to finding",
						slog.Int("finding_index", idx),
						slog.Int("num_enrichments", len(enrichments)),
					)
					// Append the enrichments to the existing ones
					// if any
					findings[idx].Finding.Enrichments = append(findings[idx].Finding.Enrichments, enrichments...)
				}
			}

		}
	}
	logger.Debug("findings annotated successfully!")
	return findings, nil
}
