package reporter

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

// NewBattlecardPrinter returns a new battlecard logger.
func NewBattlecardPrinter() battlecardLogger {
	return battlecardLogger{}
}

type battlecardLogger struct{}

// Report logs the findings in json format.
func (j battlecardLogger) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))
	enrichments := map[string]int{}
	for _, finding := range findings {
		for _, enrichment := range finding.Finding.Enrichments {
			enrichments[enrichment.Name] += 1
		}
	}
	logger.Debug("logging battlecard findings",
		slog.Int("num_enrichments", len(enrichments)),
		slog.Any("enrichments", enrichments),
	)

	logger.Info("scan finished with", slog.Int("num_findings", len(findings)))
	for enrichmentName, count := range enrichments {
		logger.Info("enrichment",
			slog.String("name", enrichmentName),
			slog.Int("count", count),
		)
	}
	return nil
}

func generateBattlecard(ctx context.Context, findings []*vf.VulnerabilityFinding) string {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	enrichments := map[string]int{}
	tools := map[string]int{}
	for _, finding := range findings {
		if finding.Finding.FindingInfo.ProductUid == nil {
			logger.Warn("finding missing product UID",
				slog.String("uid", finding.Finding.FindingInfo.Uid),
			)
		} else {
			tools[*finding.Finding.FindingInfo.ProductUid] += 1
		}
		for _, enrichment := range finding.Finding.Enrichments {
			enrichments[enrichment.Name] += 1
		}
	}

	result := "Battlecard Report\n"
	result += "=================\n"
	result += "Total Findings: " + fmt.Sprintf("%d\n", len(findings))
	result += "Enrichments:\n"
	enrichmentKeys := maps.Keys(enrichments)
	alphabeticalEnrichments := slices.Sorted(enrichmentKeys)
	for _, name := range alphabeticalEnrichments {
		result += fmt.Sprintf("  - %s: %d\n", name, enrichments[name])
	}

	result += "Findings By Tool:\n"
	toolKeys := maps.Keys(tools)
	alphabeticalTools := slices.Sorted(toolKeys)
	for _, toolName := range alphabeticalTools {
		result += fmt.Sprintf("  - %s: %d\n", toolName, tools[toolName])
	}

	return result
}
