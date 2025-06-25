package remote_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher/remote"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

func TestNewFetcher(t *testing.T) {
	var (
		ctrl     = gomock.NewController(t)
		mockDoer = NewMockDoer(ctrl)
		validCfg = fetcher.Config{
			ArtifactURL:    "https://example.com/artifact.zip",
			AuthID:         "test-key",
			AuthSecret:     "test-secret",
			BaseHttpClient: mockDoer,
		}
		emptyCfg = fetcher.Config{}
	)

	t.Run("successful creation with custom client", func(t *testing.T) {
		result, err := remote.NewFetcher(validCfg)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("successful creation with default client", func(t *testing.T) {
		cfg := validCfg
		cfg.BaseHttpClient = nil
		result, err := remote.NewFetcher(cfg)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("empty artifact url", func(t *testing.T) {
		_, err := remote.NewFetcher(emptyCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid empty artifact url")
	})
}

func TestRemoteFetcher_FetchArtifact(t *testing.T) {
	const (
		testURL          = "https://example.com/artifact.zip"
		testAccessKey    = "test-key"
		testSecretKey    = "test-secret"
		testResponseBody = "test artifact content"
	)

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer parentCancel()

	var (
		ctrl     = gomock.NewController(t)
		mockDoer = NewMockDoer(ctrl)
		doErr    = errors.New("request error")
		validCfg = fetcher.Config{
			ArtifactURL:    testURL,
			AuthID:         testAccessKey,
			AuthSecret:     testSecretKey,
			BaseHttpClient: mockDoer,
		}
		validCfgNoAuth = fetcher.Config{
			ArtifactURL:    testURL,
			BaseHttpClient: mockDoer,
		}
	)

	t.Run("successful fetch with auth", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(testResponseBody)),
		}

		mockDoer.EXPECT().
			Do(gomock.Any()).
			DoAndReturn(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, testURL, req.URL.String())

				username, password, ok := req.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, testAccessKey, username)
				assert.Equal(t, testSecretKey, password)

				return mockResp, nil
			})

		f, err := remote.NewFetcher(validCfg)
		require.NoError(t, err)

		r, err := f.FetchArtifact(ctx)
		require.NoError(t, err)
		assert.NotNil(t, r)
		defer reader.CloseReader(ctx, r)

		content, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, testResponseBody, string(content))
	})

	t.Run("successful fetch without auth", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(testResponseBody)),
		}

		mockDoer.EXPECT().
			Do(gomock.Any()).
			DoAndReturn(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, testURL, req.URL.String())

				_, _, ok := req.BasicAuth()
				assert.False(t, ok)

				return mockResp, nil
			})

		f, err := remote.NewFetcher(validCfgNoAuth)
		require.NoError(t, err)

		r, err := f.FetchArtifact(ctx)
		require.NoError(t, err)
		assert.NotNil(t, r)
		defer reader.CloseReader(ctx, r)
	})

	t.Run("request creation error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		invalidCfg := validCfg
		invalidCfg.ArtifactURL = ":/invalid-url"

		f, err := remote.NewFetcher(invalidCfg)
		require.NoError(t, err)

		_, err = f.FetchArtifact(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not create request")
	})

	t.Run("request execution error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		mockDoer.EXPECT().Do(gomock.Any()).Return(nil, doErr)

		f, err := remote.NewFetcher(validCfg)
		require.NoError(t, err)

		_, err = f.FetchArtifact(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, doErr)
		assert.Contains(t, err.Error(), "could not fetch artifact")
	})

	t.Run("non-200 status code", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		mockResp := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("")),
		}

		mockDoer.EXPECT().Do(gomock.Any()).Return(mockResp, nil)

		f, err := remote.NewFetcher(validCfg)
		require.NoError(t, err)

		_, err = f.FetchArtifact(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status code: 404")
	})

	t.Run("partial auth credentials", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		partialAuthCfg := validCfg
		partialAuthCfg.AuthSecret = ""

		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(testResponseBody)),
		}

		mockDoer.EXPECT().
			Do(gomock.Any()).
			DoAndReturn(func(req *http.Request) (*http.Response, error) {
				_, _, ok := req.BasicAuth()
				assert.False(t, ok)
				return mockResp, nil
			})

		f, err := remote.NewFetcher(partialAuthCfg)
		require.NoError(t, err)

		r, err := f.FetchArtifact(ctx)
		require.NoError(t, err)
		assert.NotNil(t, r)
		defer reader.CloseReader(ctx, r)
	})
}
