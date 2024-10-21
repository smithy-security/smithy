package files

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/pkg/utils"
)

var (
	_ Loader = (*httpFileLoader)(nil)
	// ErrInvalidURL is returns when the URL of the remote file is not a URL
	// with an HTTPS scheme.
	ErrInvalidURL = errors.New("invalid url")
	// ErrUnsuccessfulRequest is returned when the
	ErrUnsuccessfulRequest = errors.New("unsuccessful request")
)

type httpFileLoader struct {
	uri    string
	client utils.MockableRequestDoer
}

func newHTTPFileLoader(uri, targetFile string) (*httpFileLoader, error) {
	fileURL, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Errorf("%s: invalid URL: %w", uri, err)
	} else if fileURL.Scheme != "https" {
		return nil, errors.Errorf("%s: %w", uri, ErrInvalidURL)
	}

	if !strings.HasSuffix(fileURL.Path, targetFile) {
		fileURL.Path = filepath.Join(fileURL.Path, targetFile)
	}
	return &httpFileLoader{uri: fileURL.String()}, nil
}

// Load will read a file using HTTP or HTTPS
//
//revive:disable:cyclomatic High complexity score but easy to understand
//revive:disable:cognitive-complexity High complexity score but easy to understand
func (hfl *httpFileLoader) Load(ctx context.Context) (content []byte, err error) {
	if hfl.client == nil {
		hfl.client = &http.Client{}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", hfl.uri, nil)
	if err != nil {
		return nil, errors.Errorf("could not create a request: %w", err)
	}

	resp, err := hfl.client.Do(req)
	if err != nil {
		return nil, errors.Errorf("%s: could not create request: %w", hfl.uri, err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err != nil {
			err = errors.Errorf("%w: %w", closeErr, err)
		} else if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.Errorf("%s: %d: %w", hfl.uri, resp.StatusCode, ErrUnsuccessfulRequest)
	}

	content, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("%s: could not read body of response: %w", hfl.uri, err)
	}

	return content, nil
}

// Path retuns the URL of the file
func (hfl *httpFileLoader) Path() string {
	return hfl.uri
}
