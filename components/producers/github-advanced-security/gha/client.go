package gha

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/go-errors/errors"
	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"
)

type repoLister interface {
	ListAlertsForRepo(
		ctx context.Context,
		owner, repo, ref, toolName, severity string,
		pageSize int,
		currentPage string,
	) ([]*github.Alert, *github.Response, error)
}

// githubRepoLister is a real implementation of the repoLister interface that
// queries the Github API
type githubRepoLister struct {
	*github.Client
}

func newGithubRepoLister(ctx context.Context, config *ClientConfig) *githubRepoLister {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.Token},
	)

	return &githubRepoLister{
		github.NewClient(
			oauth2.NewClient(ctx, ts),
		),
	}
}

// ListAlertsForRepo queries the Github API for results obtained by various
// toolsorchestrated by Advanced Security
func (g *githubRepoLister) ListAlertsForRepo(
	ctx context.Context,
	owner, repo, ref, toolName, severity string,
	pageSize int,
	currentPage string,
) ([]*github.Alert, *github.Response, error) {
	return g.Client.CodeScanning.ListAlertsForRepo(
		ctx,
		owner,
		repo,
		&github.AlertListOptions{
			ToolName: toolName,
			Severity: severity,
			Ref:      ref,
			ListCursorOptions: github.ListCursorOptions{
				PerPage: pageSize,
				Page:    currentPage,
			},
		},
	)
}

// RepoAlertsClient is a client invoking the Github API to fetch a list of
// alerts for a repository
type APIClient struct {
	config *ClientConfig
	repoLister
}

// NewClient returns a client that can be used to query the Github API and will
// use exponential backoff to manage failed API calls
func NewClient(ctx context.Context, config *ClientConfig) *APIClient {
	return &APIClient{
		config,
		newGithubRepoLister(ctx, config),
	}
}

// ListRepoAlerts uses the underlying repoLister implementation and an
// exponential backoff algorithm to wait when it gets an erroneous result
func (a *APIClient) ListRepoAlerts(
	ctx context.Context,
) ([]*github.Alert, error) {
	var completeResults []*github.Alert
	var partialResults []*github.Alert
	var currentPage int64
	var totalPages int64 = 1
	var err error

	exponentialBackoffGenerator := backoff.NewExponentialBackOff()
	timer := time.After(1 * time.Microsecond)

	for {
		select {
		case <-timer:
			partialResults, totalPages, err = a.doCall(ctx, currentPage)
			var permanent *backoff.PermanentError
			if err != nil && errors.As(err, &permanent) {
				return nil, permanent.Unwrap()
			} else if err != nil {
				nextInterval := exponentialBackoffGenerator.NextBackOff()
				slog.Error("there was an error while querying the Github API. waiting a little bit before next API call",
					"error", err, "waitInterval", nextInterval.String())
				timer = time.After(nextInterval)
				continue
			}

			completeResults = append(completeResults, partialResults...)
			// this is to make sure that we correctly handle Github results
			// paging, because when we get the last page of results from the
			// API, the last page value which represents the total number of
			// results for a query is set to 0 while in all previous calls it
			// is set to the actual number of total pages
			if currentPage >= totalPages {
				slog.Info("done collecting results from Github")
				return completeResults, nil
			}

			currentPage += 1
			exponentialBackoffGenerator = backoff.NewExponentialBackOff()
			timer = time.After(1 * time.Microsecond)
			slog.Info("proceeding to query for next page of results", "nextPage", currentPage)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ErrWrongCredentials is returned when either the credentials are wrong, they
// are expired or they don't have the correct permissions
var ErrWrongCredentials = errors.New("authentication error from Github API, token wrong, expired or no permissions")

func (a *APIClient) doCall(ctx context.Context, currentPage int64) ([]*github.Alert, int64, error) {
	slog.Debug("listing alerts from Github API", "currentPage", currentPage)
	res, resp, err := a.repoLister.ListAlertsForRepo(
		ctx,
		a.config.RepositoryOwner,
		a.config.RepositoryName,
		a.config.Ref,
		a.config.Toolname,
		a.config.Severity,
		a.config.PageSize,
		strconv.FormatInt(currentPage, 10),
	)

	if resp != nil {
		// the credentials loaded into the client are faulty, no reason to continue
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return nil, 0, backoff.Permanent(
				errors.Errorf("%w: there was an error while connecting to the Github API: %d",
					ErrWrongCredentials, resp.StatusCode,
				),
			)
		}

		if resp.StatusCode >= http.StatusMultipleChoices {
			return nil, 0, errors.Errorf("there was an error while connecting to the Github API: %d", resp.StatusCode)
		}
	}

	if err != nil && resp == nil {
		return nil, 0, errors.Errorf("could not connect to the Github API: %w", err)
	}

	return res, int64(resp.LastPage), nil
}
