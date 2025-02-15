package gha

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/google/go-github/v69/github"
	"github.com/stretchr/testify/require"
)

type mockRepoLister struct {
	hook func(
		ctx context.Context,
		owner, repo, ref, toolName, severity string,
		pageSize int,
		currentPage string,
	) ([]*github.Alert, *github.Response, error)
}

func (m *mockRepoLister) ListAlertsForRepo(
	ctx context.Context,
	owner, repo, ref, toolName, severity string,
	pageSize int,
	currentPage string,
) ([]*github.Alert, *github.Response, error) {
	return m.hook(ctx, owner, repo, ref, toolName, severity, pageSize, currentPage)
}

func TestExponentialBackoff(t *testing.T) {
	currentAPICall := 1
	expectedPageSize := 1

	fd, err := os.OpenFile("./testdata/input.json", os.O_RDONLY, 0666)
	require.NoError(t, err)

	results := []*github.Alert{}
	require.NoError(t, json.NewDecoder(fd).Decode(&results))

	client := &APIClient{
		config: &ClientConfig{
			Token:           "ghs_mg5KTKJ11111111YN3S32222226mf",
			RepositoryOwner: "smithy-security",
			RepositoryName:  "smithy",
			Ref:             "refs/pull/735/head",
			PageSize:        expectedPageSize,
		},
		repoLister: &mockRepoLister{
			hook: func(
				ctx context.Context,
				owner, repo, ref, toolName, severity string,
				pageSize int,
				currentPage string,
			) ([]*github.Alert, *github.Response, error) {
				require.Equal(t, expectedPageSize, pageSize)
				require.Equal(t, "", severity)
				require.Equal(t, "refs/pull/735/head", ref)

				defer func() {
					currentAPICall += 1
				}()

				if currentAPICall == 1 {
					return nil, nil, errors.New("some networking error")
				} else if currentAPICall == 2 {
					return nil,
						&github.Response{
							Response: &http.Response{
								StatusCode: http.StatusInternalServerError,
							},
						},
						nil
				} else if currentAPICall == 3 {
					return results[0:1],
						&github.Response{
							Response: &http.Response{
								StatusCode: http.StatusOK,
							},
							NextPage: 2,
							LastPage: 2,
						},
						nil
				} else if currentAPICall == 4 {
					return results[1:2],
						&github.Response{
							Response: &http.Response{
								StatusCode: http.StatusOK,
							},
							NextPage: 0,
							LastPage: 0,
						},
						nil
				}

				t.FailNow()
				return nil, nil, nil
			},
		},
	}

	testContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lock := &sync.Mutex{}
	var apiResults []*github.Alert
	var listErr error
	var done bool

	go func() {
		res, err := client.ListRepoAlerts(testContext)
		lock.Lock()
		apiResults = res
		listErr = err
		done = true
		lock.Unlock()
	}()

	require.Eventuallyf(
		t,
		func() bool {
			lock.Lock()
			defer lock.Unlock()
			return done
		},
		2*time.Second,
		100*time.Millisecond,
		"API calls not finished",
	)
	require.NoError(t, listErr)
	require.Equal(t, results, apiResults)
}

func TestBadCredentials(t *testing.T) {
	client := &APIClient{
		config: &ClientConfig{
			Token:           "ghs_mg5KTKJ11111111YN3S32222226mf",
			RepositoryOwner: "smithy-security",
			RepositoryName:  "smithy",
			Ref:             "refs/pull/735/head",
			PageSize:        2,
		},
		repoLister: &mockRepoLister{
			hook: func(
				ctx context.Context,
				owner, repo, ref, toolName, severity string,
				pageSize int,
				currentPage string,
			) ([]*github.Alert, *github.Response, error) {
				return nil, &github.Response{
					Response: &http.Response{
						StatusCode: http.StatusForbidden,
					},
				}, nil
			},
		},
	}

	testContext, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := client.ListRepoAlerts(testContext)
	require.ErrorIs(t, err, ErrWrongCredentials)
}
