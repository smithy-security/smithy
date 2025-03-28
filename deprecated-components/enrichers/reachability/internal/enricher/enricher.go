package enricher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/conf"
	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/fs"
	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/logging"
	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/search"
)

type (
	enricher struct {
		cfg        *conf.Conf
		atomReader *atom.Reader
		readWriter *fs.ReadWriter
	}
)

// NewEnricher returns a new reachability enricher.
func NewEnricher(
	cfg *conf.Conf,
	atomReader *atom.Reader,
	readWriter *fs.ReadWriter,
) (*enricher, error) {
	switch {
	case cfg == nil:
		return nil, errors.New("invalid nil configuration provided")
	case atomReader == nil:
		return nil, errors.New("invalid nil atom reader provided")
	case readWriter == nil:
		return nil, errors.New("invalid nil read writer provided")
	}

	return &enricher{
		cfg:        cfg,
		atomReader: atomReader,
		readWriter: readWriter,
	}, nil
}

// Enrich looks for untagged inputs and processes them outputting if any of them is reachable.
// The reachability checks leverage atom - https://github.com/AppThreat/atom.
func (r *enricher) Enrich(ctx context.Context) error {
	var (
		logger = logging.FromContext(ctx).With(
			slog.String("producer_results_path", r.cfg.ProducerResultsPath),
			slog.String("enriched_results_path", r.cfg.EnrichedResultsPath),
			slog.String("atom_file_path", r.cfg.ATOMFilePath),
		)
	)

	logger.Debug("running enrichment step")
	logger.Debug("preparing to read tagged response...")

	taggedRes, err := r.readWriter.ReadTaggedResponse()
	if err != nil {
		return fmt.Errorf("could not read tagged response: %w", err)
	}

	logger = logger.With(slog.Int("num_tagged_resources", len(taggedRes)))
	logger.Debug("successfully read tagged response!")
	logger.Debug("preparing to read atom file...")

	reachablesRes, err := r.atomReader.Read(ctx)
	if err != nil {
		return fmt.Errorf("could not read atom reachables from path %s: %w", r.cfg.ATOMFilePath, err)
	}

	logger = logger.With(slog.Int("num_atom_reachables", len(reachablesRes.Reachables)))
	logger.Debug("successfully read atom file!")
	logger.Debug("preparing to check for reachable purls...")

	reachablePurls, err := r.atomReader.ReachablePurls(ctx, reachablesRes)
	if err != nil {
		return fmt.Errorf("could not get reachable purls: %w", err)
	}

	logger = logger.With(slog.Int("num_reachable_purls", len(reachablePurls)))
	logger.Debug("successfully checked for reachable purls!")
	logger.Debug("preparing to create a new searcher...")

	searcher, err := search.NewSearcher(reachablesRes.Reachables, reachablePurls)
	if err != nil {
		return fmt.Errorf("could not create searcher: %w", err)
	}

	logger.Debug("successfully created a new searcher!")
	logger.Debug("preparing to check for reachable targets...")

	for _, taggedEntry := range taggedRes {
		var (
			enrichedIssues []*v1.EnrichedIssue
			issues         = taggedEntry.GetIssues()
		)

		logger := logger.With(
			slog.String("tool_name", taggedEntry.GetToolName()),
			slog.String("scan_target", taggedEntry.GetToolName()),
			slog.Any("scan_info", taggedEntry.GetScanInfo()),
			slog.Int("num_issues", len(issues)),
		)

		logger.Debug("preparing to enrich issues in target...")

		for _, issue := range issues {
			// Search.
			ok, err := searcher.Search(issue.Target)
			if err != nil {
				logger.Error(
					"could not search target. Continuing...",
					slog.String("err", err.Error()),
				)
				continue
			}

			// Enrich.
			enrichedIssues = append(enrichedIssues, &v1.EnrichedIssue{
				RawIssue: issue,
				Annotations: map[string]string{
					"reachable": strconv.FormatBool(ok),
				},
			})
		}

		logger = logger.With(slog.Int("num_enriched_issues", len(enrichedIssues)))

		var numReachable int
		for _, ei := range enrichedIssues {
			v, ok := ei.Annotations["reachable"]
			if ok && v == "true" {
				_ = v
				numReachable++
			}
		}

		logger = logger.With(slog.Int("num_reachable_issues", numReachable))
		logger.Debug("successfully enriched issues in target!")

		// Write results.
		logger.Debug("preparing to write enriched results for tagged entry...")
		if err := r.readWriter.WriteEnrichedResults(taggedEntry, enrichedIssues); err != nil {
			logger.Error(
				"could not write enriched results. Continuing...",
				slog.String("err", err.Error()),
			)
			continue
		}

		logger.Debug("successfully wrote enriched results for tagged entry!")
		logger.Debug("preparing to write raw results for tagged entry...")
		if err := r.readWriter.WriteRawResults(taggedEntry); err != nil {
			logger.Error(
				"could not write raw results. Continuing...",
				slog.String("err", err.Error()),
			)
			continue
		}

		logger.Debug("successfully wrote raw results for tagged entry!")
	}

	logger.Debug("completed enrichment step!")
	return nil
}
