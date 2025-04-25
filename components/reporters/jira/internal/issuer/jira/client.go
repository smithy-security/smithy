package jira

import (
	"context"
	"net/http"
	"net/url"

	"github.com/andygrunwald/go-jira"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer"
)

type (
	IssueCreator interface {
		CreateWithContext(ctx context.Context, issue *jira.Issue) (*jira.Issue, *jira.Response, error)
	}

	UserGetter interface {
		GetSelfWithContext(ctx context.Context) (*jira.User, *jira.Response, error)
	}

	client struct {
		issuerCreator IssueCreator
		userGetter    UserGetter
		cfg           Config
	}

	Config struct {
		BaseURL            *url.URL
		Project            string
		IssueType          string
		AuthEnabled        bool
		AuthPassword       string
		AuthUsername       string
		ClientMaxRetries   uint
		SmithyInstanceID   string
		SmithyInstanceName string
		SmithyDashURL      *url.URL
	}
)

func (c Config) IsValid() error {
	switch {
	case c.BaseURL.String() == "":
		return errors.New("base URL is required")
	case c.Project == "":
		return errors.New("project is required")
	case c.AuthEnabled && (c.AuthPassword == "" || c.AuthUsername == ""):
		return errors.New("auth password and auth username are required when auth is enabled")
	}
	return nil
}

func NewClient(ctx context.Context, cfg Config) (*client, error) {
	if err := cfg.IsValid(); err != nil {
		return nil, errors.Errorf("invalid config: %w", err)
	}

	transport := http.DefaultTransport
	if cfg.AuthEnabled {
		transport = &jira.BasicAuthTransport{
			Username: cfg.AuthUsername,
			Password: cfg.AuthPassword,
		}
	}

	rc, err := retry.NewClient(retry.Config{
		BaseTransport: transport,
		MaxRetries:    cfg.ClientMaxRetries,
		Logger:        component.LoggerFromContext(ctx),
	})
	if err != nil {
		return nil, errors.Errorf("failed to create retry client: %w", err)
	}

	jc, err := jira.NewClient(rc, cfg.BaseURL.String())
	if err != nil {
		return nil, errors.Errorf("failed to create jira client: %w", err)
	}

	return &client{
		cfg:           cfg,
		issuerCreator: jc.Issue,
		userGetter:    jc.User,
	}, nil
}

func (c *client) BatchCreate(ctx context.Context, issues []issuer.Issue) (uint, bool, error) {
	u, _, err := c.userGetter.GetSelfWithContext(ctx)
	if err != nil {
		return 0, false, errors.Errorf("failed to get user info: %w", err)
	}

	var (
		errs       error
		numCreated uint
	)

	var jiraIssues = make([]jira.Issue, 0, len(issues))
	for _, issue := range issues {
		jiraIssues = append(jiraIssues, c.toJiraIssue(u, issue))
	}

	for _, jiraIssue := range jiraIssues {
		if _, _, err := c.issuerCreator.CreateWithContext(ctx, &jiraIssue); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		numCreated++
	}

	if errs != nil {
		return numCreated, numCreated > 0, errors.Errorf("failed to create issues: %w", errs)
	}

	return numCreated, numCreated > 0, nil
}

func (c *client) toJiraIssue(user *jira.User, issue issuer.Issue) jira.Issue {
	return jira.Issue{
		Fields: &jira.IssueFields{
			Description: issue.Description,
			Summary:     issue.Summary,
			Type: jira.IssueType{
				Name: c.cfg.IssueType,
			},
			Reporter: &jira.User{
				AccountID: user.AccountID,
			},
			Project: jira.Project{
				Key: c.cfg.Project,
			},
		},
	}
}
