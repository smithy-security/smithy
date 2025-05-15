package reporter

import (
	"context"
	"fmt"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
)

type (
	IssueCreator interface {
		CreateIssue(ctx context.Context, req linear.CreateIssueRequest) (*linear.CreateIssueResponse, error)
	}
	reporter struct {
		issueCreator IssueCreator
	}
)

func New(issueCreator IssueCreator) (*reporter, error) {
	if issueCreator == nil {
		return nil, fmt.Errorf("issue creator cannot be nil")
	}
	return &reporter{issueCreator: issueCreator}, nil
}

func (r *reporter) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	return nil
}
