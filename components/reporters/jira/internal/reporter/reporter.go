package reporter

import (
	"context"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer"
)

type (
	IssueCreator interface {
		BatchCreate(ctx context.Context, issues []issuer.Issue) (uint, bool, error)
	}
	reporter struct {
		issuer IssueCreator
	}
)

func New(issuer IssueCreator) (*reporter, error) {
	if issuer == nil {
		return nil, errors.New("invalid nil IssueCreator")
	}
	return &reporter{
		issuer: issuer,
	}, nil
}

func (r *reporter) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := component.LoggerFromContext(ctx)

	logger.Debug("preparing to report issues...")
	if len(findings) == 0 {
		logger.Debug("no findings to report, skipping")
		return nil
	}

	logger.Debug("preparing to map findings to report...")
	var issues = make([]issuer.Issue, 0, len(findings))
	for _, finding := range findings {
		issues = append(issues, toIssues(finding)...)
	}
	logger.Debug("successfully mapped findings to report!")

	logger.Debug("preparing to create findings...")
	numCreated, ok, err := r.issuer.BatchCreate(ctx, issues)
	switch {
	case err != nil:
		if !ok {
			return errors.Errorf("couldn't batch create issues: %w", err)
		}
		logger.Debug(
			"failed to create some findings",
			slog.Int("num_created", int(numCreated)),
			slog.Int("delta", len(findings)-int(numCreated)),
		)
		return nil
	case !ok:
		logger.Debug("no findings were created, skipping")
		return nil
	}
	logger.Debug("successfully created findings!")

	logger.Debug("successfully reported issues!")
	return nil
}

func toIssues(vf *vf.VulnerabilityFinding) []issuer.Issue {
	var issues = make([]issuer.Issue, 0, len(vf.Finding.GetVulnerabilities()))
	for _, f := range vf.Finding.GetVulnerabilities() {
		issues = append(issues, issuer.Issue{
			Description: f.GetDesc(),
			Summary:     f.GetTitle(),
			ID:          vf.ID,
			Priority:    f.GetSeverity(),
			Reporter:    f.GetVendorName(),
		})
	}
	return issues
}
