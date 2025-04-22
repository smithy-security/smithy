package jira

import (
	"log/slog"
	"net/http"
	"net/http/httputil"

	"github.com/cenkalti/backoff/v5"
	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
)

type (
	retryOption func(*retry) error

	retry struct {
		maxRetries           uint
		doer                 Doer
		retryableStatusCodes map[int]struct{}
		acceptedStatusCodes  map[int]struct{}
	}

	// Doer allows to customise Do's behaviour for unit testing.
	Doer interface {
		Do(*http.Request) (*http.Response, error)
	}
)

// RetryWithDoer allows customising the Doer.
func RetryWithDoer(doer Doer) retryOption {
	return func(r *retry) error {
		if doer == nil {
			return errors.New("invalid nil doer")
		}
		r.doer = doer
		return nil
	}
}

// NewHttpClient returns a new OAuth prManager initialise
// with a StaticTokenSource and retry mechanism.
func NewHttpClient(transport http.RoundTripper, maxRetries uint, opts ...retryOption) (*http.Client, error) {
	switch {
	case maxRetries == 0:
		return nil, errors.New("invalid zero value for max retries")
	}

	var (
		cli = http.DefaultClient
	)

	// Perhaps some of these bits can be configurable but these defaults should do it for now.
	r := &retry{
		maxRetries: maxRetries,
		doer: &http.Client{
			Transport: transport,
		},
		retryableStatusCodes: map[int]struct{}{
			http.StatusTooManyRequests:    {},
			http.StatusRequestTimeout:     {},
			http.StatusGatewayTimeout:     {},
			http.StatusBadGateway:         {},
			http.StatusServiceUnavailable: {},
		},
		acceptedStatusCodes: map[int]struct{}{
			http.StatusCreated:   {},
			http.StatusAccepted:  {},
			http.StatusNoContent: {},
			http.StatusOK:        {},
		},
	}

	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	cli.Transport = r
	return cli, nil
}

// RoundTrip implements a http transport Roundtripper with retry capabilities.
func (re *retry) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		logger      = component.LoggerFromContext(req.Context())
		currAttempt uint
		retryableOp = func() (*http.Response, error) {
			resp, err := re.doer.Do(req)
			switch {
			case err != nil:
				return resp, backoff.Permanent(err)
			case resp == nil:
				return nil, backoff.Permanent(errors.New("invalid nil response"))
			}

			_, isAcceptedStatus := re.acceptedStatusCodes[resp.StatusCode]
			_, isRetryableStatus := re.retryableStatusCodes[resp.StatusCode]

			switch {
			case !isAcceptedStatus && currAttempt >= re.maxRetries:
				return resp, backoff.Permanent(
					errors.Errorf(
						"maximum number of retries exceeded: %d",
						currAttempt,
					),
				)
			case !isAcceptedStatus && isRetryableStatus:
				nextRetryInSeconds := fibNextRetry(currAttempt)

				logger.Debug(
					"retryable status code, retrying",
					slog.Int("retry_in_seconds", nextRetryInSeconds),
					slog.Int("curr_attempt", int(currAttempt)),
					slog.Int("status_code", resp.StatusCode),
				)
				currAttempt++
				return resp, backoff.RetryAfter(nextRetryInSeconds)
			case !isAcceptedStatus && !isRetryableStatus:
				bb, err := httputil.DumpResponse(resp, true)
				if err != nil {
					logger.Error(
						"failed to dump response",
						slog.String("error", err.Error()),
					)
				}
				logger.Error(
					"unexpected response",
					slog.Int("status_code", resp.StatusCode),
					slog.String("raw_body", string(bb)),
				)
				return resp, backoff.Permanent(errors.Errorf("invalid status code: %d", resp.StatusCode))
			}

			return resp, nil
		}
	)

	result, err := backoff.Retry(
		req.Context(),
		retryableOp,
	)
	if err != nil {
		return result, errors.Errorf("could not process backoff result: %w", err)
	}

	return result, nil
}

func fibNextRetry(attempt uint) int {
	switch attempt {
	case 0:
		return 0
	case 1:
		return 1
	default:
		return fibNextRetry(attempt-1) + fibNextRetry(attempt-2)
	}
}
