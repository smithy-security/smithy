package clientmock

import (
	"context"

	"github.com/google/go-github/v69/github"
)

// MockClient mocks the two methods of google's github client we use
type MockClient struct {
	ListRepoAlertsCallback           func(string, string, *github.AlertListOptions) ([]*github.Alert, *github.Response, error)
	ListRepoDependabotAlertsCallback func(string, string, *github.ListAlertsOptions) ([]*github.DependabotAlert, *github.Response, error)
}

// NewMockClient returns a mock github client
func NewMockClient() MockClient {
	return MockClient{}
}

// ListRepoAlerts calls the mocked callback
func (m MockClient) ListRepoAlerts(_ context.Context, owner string, repo string, opt *github.AlertListOptions) ([]*github.Alert, *github.Response, error) {
	return m.ListRepoAlertsCallback(owner, repo, opt)
}

// ListRepoDependabotAlerts calls the mocked callback
func (m MockClient) ListRepoDependabotAlerts(_ context.Context, owner string, repo string, opt *github.ListAlertsOptions) ([]*github.DependabotAlert, *github.Response, error) {
	return m.ListRepoDependabotAlertsCallback(owner, repo, opt)
}
