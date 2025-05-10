package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-errors/errors"
	"github.com/machinebox/graphql"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
)

var (
	createIssueRequest = graphql.NewRequest(`
	mutation IssueCreate($input: IssueCreateInput!) {
		issueCreate(input: $input) {
			success
			issue {
				id
				title
				identifier
			}
		}
	}`)
)

type (
	client struct {
		gc *graphql.Client
	}

	AuthRoundTripper struct {
		APIKey string
	}

	Config struct {
		Client  *http.Client
		BaseURL *url.URL
	}

	createIssueResponse struct {
		IssueCreate struct {
			Success bool
			Issue   struct {
				ID         string
				Title      string
				Identifier string
			}
		}
	}
)

func NewAuthRoundTripper(apiKey string) (*AuthRoundTripper, error) {
	if apiKey == "" {
		return nil, errors.New("invalid empty api key")
	}
	return &AuthRoundTripper{APIKey: apiKey}, nil
}

func (rt *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", rt.APIKey)
	return http.DefaultTransport.RoundTrip(req)
}

func New(conf Config) (*client, error) {
	if err := conf.validate(); err != nil {
		return nil, errors.Errorf("invalid config: %w", err)
	}

	var clientOpts []graphql.ClientOption
	if conf.Client != nil {
		clientOpts = append(clientOpts, graphql.WithHTTPClient(conf.Client))
	}

	return &client{
		gc: graphql.NewClient(
			conf.BaseURL.String(),
			clientOpts...,
		),
	}, nil
}

func (c Config) validate() error {
	switch {
	case c.BaseURL == nil || c.BaseURL.String() == "":
		return errors.New("invalid empty base url")
	}
	return nil
}

func (c *client) CreateIssue(ctx context.Context, req linear.CreateIssueRequest) (*linear.CreateIssueResponse, error) {
	createIssueRequest.Var("input", map[string]any{
		"teamId":      "YOUR_TEAM_ID",
		"title":       "Issue created from Golang",
		"description": "This is an issue created using the Linear API from a Golang application.",
		"priority":    2,
	})

	var resp createIssueResponse
	if err := c.gc.Run(ctx, createIssueRequest, &resp); err != nil {
		return nil, errors.Errorf("failed to execute createIssue request query: %w", err)
	}

	return &linear.CreateIssueResponse{}, nil
}
