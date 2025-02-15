package wrapper

import (
	"context"
	"log/slog"

	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"
)

// Wrapper is the wrapper interface that allows the github client to be pluggable
type Wrapper interface {
	// ListRepoAlerts is a thin wrapper around github's equivalent
	ListRepoAlerts(ctx context.Context, owner string, repo string, opt *github.AlertListOptions) ([]*github.Alert, *github.Response, error)

	// ListRepoDependabotAlerts is a thin wrapper around github's equivalent
	ListRepoDependabotAlerts(ctx context.Context, owner string, repo string, opt *github.ListAlertsOptions) ([]*github.DependabotAlert, *github.Response, error)
}

// Client is the wrapper around google's go-github client
type Client struct {
	Client *github.Client
}

// NewClient returns an actual github client
func NewClient(token string) Client {
	if token == "" {
		slog.Error("Cannot authenticate to github, token is empty")
	}
	// authenticate to github, start a client
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	oAuthClient := oauth2.NewClient(context.Background(), ts)
	// create new github client with accessToken
	return Client{
		Client: github.NewClient(oAuthClient),
	}
}

// ListRepoAlerts is a thin wrapper around github's ListRepoAlerts
func (gc Client) ListRepoAlerts(ctx context.Context, owner string, repo string, opt *github.AlertListOptions) ([]*github.Alert, *github.Response, error) {
	return gc.Client.CodeScanning.ListAlertsForRepo(ctx, owner, repo, opt)
}

// ListRepoDependabotAlerts is a thin wrapper around github's ListRepoDependabotAlerts
func (gc Client) ListRepoDependabotAlerts(ctx context.Context, owner string, repo string, opt *github.ListAlertsOptions) ([]*github.DependabotAlert, *github.Response, error) {
	return gc.Client.Dependabot.ListRepoAlerts(ctx, owner, repo, opt)
}
