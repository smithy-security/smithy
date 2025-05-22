package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-errors/errors"
	"github.com/machinebox/graphql"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
)

type (
	client struct {
		gc       *graphql.Client
		labelIDs map[string]string
		cfg      Config
	}

	// AuthRoundTripper injects the Auth header in each request.
	AuthRoundTripper struct {
		APIKey string
	}

	// Config contains the client's config.
	Config struct {
		Client           *http.Client
		BaseURL          *url.URL
		TeamID           string
		APIKey           string
		RequestBatchSize int
		IssueLabelsNames []string
	}

	// GetTeamsResponse maps the raw response for getting teams.
	GetTeamsResponse struct {
		Teams struct {
			Nodes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"nodes"`
		} `json:"teams"`
	}

	// BatchIssueCreateResult maps the raw response for creating one issue.
	BatchIssueCreateResult struct {
		Success bool `json:"success"`
		Issue   struct {
			ID         string `json:"id"`
			Title      string `json:"title"`
			Identifier string `json:"identifier"`
			URL        string `json:"url"`
		} `json:"issue"`
	}

	// BatchCreateResponse maps the raw response for creating issues in batches.
	BatchCreateResponse struct {
		IssueCreate BatchIssueCreateResult `json:"issueCreate"`
	}

	// LabelResponse maps label's response.
	LabelResponse struct {
		IssueLabels struct {
			Nodes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"nodes"`
		} `json:"issueLabels"`
	}
)

// NewAuthRoundTripper returns a new auth round tripper.
func NewAuthRoundTripper(apiKey string) (*AuthRoundTripper, error) {
	if apiKey == "" {
		return nil, errors.New("invalid empty api key")
	}
	return &AuthRoundTripper{APIKey: apiKey}, nil
}

// RoundTrip adds the auth header to each request.
func (rt *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", rt.APIKey)
	return http.DefaultTransport.RoundTrip(req)
}

// New returns a new client which also looks up for passed labels.
func New(ctx context.Context, conf Config) (*client, error) {
	if err := conf.validate(); err != nil {
		return nil, errors.Errorf("invalid config: %w", err)
	}

	var clientOpts []graphql.ClientOption
	if conf.Client != nil {
		clientOpts = append(clientOpts, graphql.WithHTTPClient(conf.Client))
	}

	c := &client{
		cfg: conf,
		gc: graphql.NewClient(
			conf.BaseURL.String(),
			clientOpts...,
		),
	}

	labelIDNames, err := c.GetLabelIDs(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to get label ids: %w", err)
	}

	return &client{
		labelIDs: labelIDNames,
		cfg:      conf,
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
	case c.TeamID == "":
		return errors.New("invalid empty team id")
	case c.APIKey == "":
		return errors.New("invalid empty api key")
	case c.RequestBatchSize <= 0:
		return errors.New("invalid request batch size")
	}
	return nil
}

// GetTeams is a helper method used to find teams' information.
func (c *client) GetTeams(ctx context.Context) (*linear.GetTeamsResponse, error) {
	var (
		req = graphql.NewRequest(`
		query {
			teams {
				nodes {
					id
					name
				}
			}
		}`)
		resp GetTeamsResponse
	)

	if err := c.gc.Run(ctx, req, &resp); err != nil {
		return nil, errors.Errorf("could not get teams: %w", err)
	}

	var linearResp linear.GetTeamsResponse
	for _, t := range resp.Teams.Nodes {
		linearResp.Teams = append(
			linearResp.Teams,
			linear.Team{
				ID:   t.ID,
				Name: t.Name,
			},
		)
	}

	return &linearResp, nil
}

// BatchCreateIssues creates issues in batches.
func (c *client) BatchCreateIssues(ctx context.Context, requests []linear.CreateIssueRequest) ([]linear.CreateIssueResponse, error) {
	if len(requests) == 0 {
		return nil, errors.New("no issues to create")
	}

	var (
		allResponses []linear.CreateIssueResponse
		errs         error
	)
	for i := 0; i < len(requests); i += c.cfg.RequestBatchSize {
		end := i + c.cfg.RequestBatchSize
		if end > len(requests) {
			end = len(requests)
		}

		responses, err := c.createIssuesBatch(ctx, requests[i:end])
		if err != nil {
			errs = errors.Join(errs, errors.Errorf("failed to create batch starting at index %d: %w", i, err))
			continue
		}

		allResponses = append(allResponses, responses...)
	}

	return allResponses, errs
}

func (c *client) createIssuesBatch(ctx context.Context, requests []linear.CreateIssueRequest) ([]linear.CreateIssueResponse, error) {
	var (
		numReqs  = len(requests)
		mutation = c.buildIssuesBatchMutation(numReqs)
		req      = graphql.NewRequest(mutation)
	)

	for i, issueReq := range requests {
		var labelIDs = make([]string, 0, len(c.labelIDs))
		for _, id := range c.labelIDs {
			labelIDs = append(labelIDs, id)
		}

		req.Var(fmt.Sprintf("input%d", i), map[string]any{
			"teamId":      c.cfg.TeamID,
			"title":       issueReq.Title,
			"description": issueReq.Description,
			"priority":    issueReq.Priority,
			"labelIds":    labelIDs,
		})
	}

	var rawResp json.RawMessage
	err := c.gc.Run(ctx, req, &rawResp)
	if err != nil {
		return nil, errors.Errorf("failed to execute batch create request: %w", err)
	}

	return c.parseIssuesBatchResponse(rawResp, numReqs)
}

func (c *client) parseIssuesBatchResponse(rawResp json.RawMessage, numReqs int) ([]linear.CreateIssueResponse, error) {
	var resp map[string]BatchIssueCreateResult
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, errors.Errorf("failed to unmarshal batch response: %w", err)
	}

	var (
		responses []linear.CreateIssueResponse
		errs      error
	)
	for i := 0; i < numReqs; i++ {
		alias := fmt.Sprintf("issue%d", i)

		issueResp, exists := resp[alias]
		if !exists {
			errs = errors.Join(errs, errors.Errorf("missing response for issue %d", i))
			continue
		}

		if !issueResp.Success {
			errs = errors.Join(errs, errors.Errorf("failed to create issue %d, check logs for more info", i))
			continue
		}

		responses = append(responses, linear.CreateIssueResponse{
			ID:  issueResp.Issue.ID,
			URL: issueResp.Issue.URL,
		})
	}

	return responses, errs
}

func (c *client) buildIssuesBatchMutation(numReqs int) string {
	var (
		variables = make([]string, 0, numReqs)
		mutations = make([]string, 0, numReqs)
	)

	for i := 0; i < numReqs; i++ {
		variables = append(
			variables,
			fmt.Sprintf("$input%d: IssueCreateInput!", i),
		)
		mutations = append(
			mutations,
			fmt.Sprintf(`
            issue%d: issueCreate(input: $input%d) {
                success
                issue {
                    id
                    title
                    identifier
                    url
                }
            }`,
				i,
				i,
			),
		)
	}

	return fmt.Sprintf(`
        mutation BatchCreateIssues(%s) {
            %s
        }
    `,
		strings.Join(variables, ", "),
		strings.Join(mutations, ""),
	)
}

// GetLabelIDs finds the label ids at run time.
func (c *client) GetLabelIDs(ctx context.Context) (map[string]string, error) {
	if len(c.cfg.IssueLabelsNames) == 0 {
		return nil, nil
	}

	var (
		labelIDs         = make(map[string]string, len(c.cfg.IssueLabelsNames))
		findLabelRequest = graphql.NewRequest(`
		query FindLabel($filter: IssueLabelFilter!) {
			issueLabels(filter: $filter) {
				nodes {
					id
					name
				}
			}
		}`)
	)

	for _, label := range c.cfg.IssueLabelsNames {
		findLabelRequest.Var("filter", map[string]any{
			"name": map[string]any{
				"eq": label,
			},
		})

		var resp LabelResponse
		err := c.gc.Run(ctx, findLabelRequest, &resp)
		if err != nil {
			return nil, errors.Errorf("failed to search for vulnerability label '%s': %w", label, err)
		}

		for _, l := range resp.IssueLabels.Nodes {
			if l.Name == label {
				labelIDs[l.Name] = l.ID
			}
		}
	}

	return labelIDs, nil
}
