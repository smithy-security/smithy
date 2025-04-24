package annotation

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom/purl"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/conf"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/logging"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/search"
)

type (
	reachabilityAnnotator struct {
		cfg            *conf.Conf
		atomReader     *atom.Reader
		annotationName string
		providerName   string
	}
)

// NewReachabilityAnnotator returns a new reachability enricher.
func NewReachabilityAnnotator(cfg *conf.Conf) *reachabilityAnnotator {
	return &reachabilityAnnotator{
		cfg:            cfg,
		annotationName: "Reachable-Code",
		providerName:   "reachability-enricher",
	}
}

// Annotate adds annotated values to passed findings.
func (ra *reachabilityAnnotator) Annotate(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) ([]*vf.VulnerabilityFinding, error) {
	var (
		logger = component.LoggerFromContext(ctx).
			With(slog.Int("num_findings", len(findings))).
			With(slog.String("provider_name", ra.providerName))
	)

	logger.Debug("preparing to annotate findings...")

	purlParser, err := purl.NewParser()
	if err != nil {
		return nil, errors.Errorf("could not initialize purl parser: %w", err)
	}

	ar, err := atom.NewReader(ra.cfg.ATOMFileGlob, purlParser)
	if err != nil {
		return nil, errors.Errorf("could not initialize atom reader: %w", err)
	}

	ra.atomReader = ar
	findings, err = ra.Enrich(ctx, findings)
	if err != nil {
		return nil, errors.Errorf("could not enrich findings err: %w", err)
	}
	logger.Debug("findings annotated successfully!")
	return findings, nil
}

// Enrich looks for untagged inputs and processes them outputting if any of them is reachable.
// The reachability checks leverage atom - https://github.com/AppThreat/atom.
func (ra *reachabilityAnnotator) Enrich(ctx context.Context, findings []*vf.VulnerabilityFinding) ([]*vf.VulnerabilityFinding, error) {
	var (
		logger = logging.FromContext(ctx).With(
			slog.String("atom_file_glob", ra.cfg.ATOMFileGlob),
		)
	)

	logger.Debug("running enrichment step")
	logger.Debug("preparing to read response...")

	logger = logger.With(slog.Int("num_tagged_resources", len(findings)))
	logger.Debug("preparing to read atom file...")

	reachablesRes, err := ra.atomReader.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not read atom reachables from paths %s: %w", ra.cfg.ATOMFileGlob, err)
	}

	for _, response := range reachablesRes {
		logger = logger.With(slog.Int("num_atom_reachables", len(response.Reachables)))
		logger.Debug("successfully read atom files!")
		logger.Debug("preparing to check for reachable purls...")

		reachablePurls, err := ra.atomReader.ReachablePurls(ctx, response)
		if err != nil {
			return nil, fmt.Errorf("could not get reachable purls: %w", err)
		}

		logger = logger.With(slog.Int("num_reachable_purls", len(reachablePurls)))
		logger.Debug("successfully checked for reachable purls!")
		logger.Debug("preparing to create a new searcher...")

		searcher, err := search.NewSearcher(response.Reachables, reachablePurls)
		if err != nil {
			return nil, fmt.Errorf("could not create searcher: %w", err)
		}

		logger.Debug("successfully created a new searcher!")
		logger.Debug("preparing to check for reachable targets...")
		numEnriched := 0
		numReachable := 0
		atomPurlParser, err := purl.NewParser()
		if err != nil {
			return nil, errors.Errorf("could not initialize atom purl parser err: %w", err)
		}
		for idx, finding := range findings {
			vendor := ""
			switch {
			case finding.Finding.FindingInfo.ProductUid != nil:
				vendor = *finding.Finding.FindingInfo.ProductUid
			case finding.Finding.Metadata != nil:
				if finding.Finding.Metadata.Product != nil && finding.Finding.Metadata.Product.Name != nil {
					vendor = *finding.Finding.Metadata.Product.Name
				}
			case len(finding.Finding.Vulnerabilities) > 0:
				if finding.Finding.Vulnerabilities[0].VendorName != nil {
					vendor = *finding.Finding.Vulnerabilities[0].VendorName
				}
			default:
				vendor = ""
			}
			logger := logger.With(
				slog.String("vendor", vendor),
				slog.Any("scan_id", finding.ID),
				slog.Int("num_vulns", len(finding.Finding.Vulnerabilities)),
			)
			logger.Debug("preparing to enrich issues in target...")
			for _, vuln := range finding.Finding.Vulnerabilities {
				for _, pkg := range vuln.AffectedPackages {
					parsedPurls, err := atomPurlParser.ParsePurl(*pkg.Purl)
					if err != nil {
						logger.Error(
							"could not search affected package. Continuing...",
							slog.String("err", err.Error()))
						continue
					}
					var reachable bool
					var reachableEnrichment *ocsf.Enrichment
					for _, p := range parsedPurls {
						re, reached, err := ra.isReachable(searcher, p)
						if err != nil {
							logger.Error(
								"could not search affected package. Continuing...",
								slog.String("err", err.Error()),
							)
							continue
						}
						reachable = reached
						reachableEnrichment = re
						if reached {
							break
						}
					}
					if reachable {
						numReachable += 1
					}
					numEnriched += 1
					findings[idx].Finding.Enrichments = append(findings[idx].Finding.Enrichments, reachableEnrichment)
				}

				for _, code := range vuln.AffectedCode {
					reachableEnrichment, reachable, err := ra.isReachable(searcher, ra.makeCodeString(code))
					if err != nil {
						logger.Error(
							"could not search affected package. Continuing...",
							slog.String("err", err.Error()),
						)
					}
					if reachable {
						numReachable += 1
					}
					numEnriched += 1
					findings[idx].Finding.Enrichments = append(findings[idx].Finding.Enrichments, reachableEnrichment)
				}
			}

			logger = logger.With(slog.Int("num_enriched_issues", numEnriched))
			logger = logger.With(slog.Int("num_reachable_issues", numReachable))
			logger.Debug("successfully enriched issues in target!")
		}
		logger.Debug("completed enrichment step!")
	}
	return findings, nil
}

func (ra *reachabilityAnnotator) makeCodeString(c *ocsf.AffectedCode) string {
	return fmt.Sprintf("%s:%d-%d", *c.File.Path, *c.StartLine, *c.EndLine)
}

func (ra *reachabilityAnnotator) isReachable(searcher *search.Searcher, target string) (*ocsf.Enrichment, bool, error) {
	ok, err := searcher.Search(target)
	if err != nil {
		return nil, false, err
	}

	return &ocsf.Enrichment{
		Name:     ra.annotationName,
		Value:    fmt.Sprintf("%t", ok),
		Provider: &ra.providerName,
	}, ok, nil
}
