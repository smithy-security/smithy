package jira

import (
	"context"
	"net/http"
	"net/url"

	"github.com/andygrunwald/go-jira"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer"
)

type (
	// IssueCreator describes how to create issues.
	IssueCreator interface {
		CreateWithContext(ctx context.Context, issue *jira.Issue) (*jira.Issue, *jira.Response, error)
	}

	// UserGetter describes how to get user info of the underlying username/password.
	UserGetter interface {
		GetSelfWithContext(ctx context.Context) (*jira.User, *jira.Response, error)
	}

	client struct {
		issuerCreator IssueCreator
		userGetter    UserGetter
		cfg           Config
	}

	// Config contains the Jira configuration.
	Config struct {
		// BaseURL is the base URL of the Jira server.
		BaseURL *url.URL
		// Project is the Jira project on which issues should be opened.
		Project string
		// IssueType specifies the issue type. Task is the default.
		IssueType string
		// AuthEnabled allows to switch on or off the authentication to Jira.
		AuthEnabled bool
		// AuthPassword is the password or API Token associated to the user that makes requests to Jira.
		AuthPassword string
		// AuthUsername is the username or API Token associated to the user that makes requests to Jira.
		AuthUsername string
		// ClientMaxRetries configures how many retries we should do when the API calls to Jira fail
		// for retryable status codes (i.e. 503).
		ClientMaxRetries uint
		// SmithyInstanceID is the uuid representing the instance id in smithy. This is used for enriching the finding.
		SmithyInstanceID string
		// SmithyInstanceName is the instance name in smithy. This is used for enriching the finding.
		SmithyInstanceName string
		// SmithyDashURL is instance URL backing a smithy instance.
		SmithyDashURL *url.URL
	}
)

// IsValid checks if the configuration is valid.
func (c Config) IsValid() error {
	switch {
	case c.BaseURL == nil || c.BaseURL.String() == "":
		return errors.New("base URL is required")
	case c.Project == "":
		return errors.New("project is required")
	case c.AuthEnabled && (c.AuthPassword == "" || c.AuthUsername == ""):
		return errors.New("auth password and auth username are required when auth is enabled")
	}
	return nil
}

// NewTestClient is used to get a test client in tests.
func NewTestClient(issuerCreator IssueCreator, userGetter UserGetter, cfg Config) (*client, error) {
	switch {
	case issuerCreator == nil:
		return nil, errors.New("issuer creator is required")
	case userGetter == nil:
		return nil, errors.New("user getter is required")
	}

	return &client{
		issuerCreator: issuerCreator,
		userGetter:    userGetter,
		cfg:           cfg,
	}, cfg.IsValid()
}

// NewClient returns a new Jira client.
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
		Logger:        componentlogger.LoggerFromContext(ctx),
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

// BatchCreate creates passed issues on Jira.
func (c *client) BatchCreate(ctx context.Context, issues []issuer.Issue) (uint, bool, error) {
	if len(issues) == 0 {
		return 0, false, nil
	}

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
