package reporter

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"text/template"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/config"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
)

//go:embed issue.tpl
var issueTpl string

type (
	// IssueCreator abstracts issue creation.
	IssueCreator interface {
		BatchCreateIssues(ctx context.Context, requests []linear.CreateIssueRequest) ([]linear.CreateIssueResponse, error)
	}
	reporter struct {
		cfg          config.Config
		issueCreator IssueCreator
	}
)

// New returns a new reporter.
func New(cfg config.Config, issueCreator IssueCreator) (*reporter, error) {
	if issueCreator == nil {
		return nil, fmt.Errorf("issue creator cannot be nil")
	}
	return &reporter{
		cfg:          cfg,
		issueCreator: issueCreator,
	}, nil
}

// Report reports findings to Linear.
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

	tpl, err := template.New("issue").Parse(issueTpl)
	if err != nil {
		return errors.Errorf("could not parse issue template: %w", err)
	}

	logger.Debug("preparing to map findings to report...")
	var issuesReq = make([]linear.CreateIssueRequest, 0, len(findings))
	for _, finding := range findings {
		prepIssues, err := r.getIssueRequests(tpl, finding)
		if err != nil {
			return errors.Errorf("could not prepare issues: %w", err)
		}
		issuesReq = append(issuesReq, prepIssues...)
	}
	logger.Debug("successfully mapped findings to report!")

	logger.Debug("preparing to batch create issues...")
	issues, err := r.issueCreator.BatchCreateIssues(ctx, issuesReq)
	if err != nil {
		if len(issues) == 0 {
			return errors.Errorf("could not batch create issues: %w", err)
		}
		return errors.Errorf("partially created issues. Check logs for more details: %w", err)
	}
	logger.Debug(
		"successfully batch creating issues!",
		slog.Int("num_issues", len(issues)),
		slog.Any("issues", issues),
	)

	return nil
}
