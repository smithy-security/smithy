package remote

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
)

type (
	// Doer abstracts requests' execution.
	Doer interface {
		Do(*http.Request) (*http.Response, error)
	}

	// HTTPFetcher uses HTTP to fetch an artefact
	HTTPFetcher struct {
		doer Doer
		cfg  fetcher.Config
	}
)

// NewFetcher returns a new http fetcher.
func NewFetcher(cfg fetcher.Config) (HTTPFetcher, error) {
	if cfg.ArtifactURL == "" {
		return HTTPFetcher{}, errors.New("invalid empty artifact url")
	}

	var doer = cfg.BaseHTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}

	return HTTPFetcher{
		doer: doer,
		cfg:  cfg,
	}, nil
}

// FetchArtifact fetches an artifact using BasicAuth, if provided.
func (h HTTPFetcher) FetchArtifact(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.ArtifactURL, nil)
	if err != nil {
		return nil, errors.Errorf("could not create request: %w", err)
	}

	if h.cfg.AuthID != "" && h.cfg.AuthSecret != "" {
		logger.LoggerFromContext(ctx).Debug(
			"authenticating with auth id and secret",
			slog.String("auth_id", fetcher.Redact(h.cfg.AuthID)),
			slog.String("auth_secret", fetcher.Redact(h.cfg.AuthSecret)),
		)
		req.SetBasicAuth(h.cfg.AuthID, h.cfg.AuthSecret)
	}

	resp, err := h.doer.Do(req)
	switch {
	case err != nil:
		return nil, errors.Errorf("could not fetch artifact: %w", err)
	case resp.StatusCode != http.StatusOK:
		return nil, errors.Errorf("could not fetch artifact, unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, nil
}
