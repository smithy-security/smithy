package remote

import (
	"context"
	"io"
	"net/http"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
)

type (
	// Doer abstracts requests' execution.
	Doer interface {
		Do(*http.Request) (*http.Response, error)
	}

	remoteFetcher struct {
		doer Doer
		cfg  fetcher.Config
	}
)

// NewFetcher returns a new http fetcher.
func NewFetcher(cfg fetcher.Config) (remoteFetcher, error) {
	switch {
	case cfg.ArtifactURL == "":
		return remoteFetcher{}, errors.New("invalid empty artifact url")
	}

	var doer = cfg.BaseHttpClient
	if doer == nil {
		doer = http.DefaultClient
	}

	return remoteFetcher{
		doer: doer,
		cfg:  cfg,
	}, nil
}

// FetchArtifact fetches an artifact using BasicAuth, if provided.
func (f remoteFetcher) FetchArtifact(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.ArtifactURL, nil)
	if err != nil {
		return nil, errors.Errorf("could not create request: %w", err)
	}

	if f.cfg.AuthID != "" && f.cfg.AuthSecret != "" {
		req.SetBasicAuth(f.cfg.AuthID, f.cfg.AuthSecret)
	}

	resp, err := f.doer.Do(req)
	switch {
	case err != nil:
		return nil, errors.Errorf("could not fetch artifact: %w", err)
	case resp.StatusCode != http.StatusOK:
		return nil, errors.Errorf("could not fetch artifact, unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, nil
}
