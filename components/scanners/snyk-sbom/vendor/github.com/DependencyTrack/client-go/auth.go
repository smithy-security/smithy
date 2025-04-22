package dtrack

import (
	"context"
	"fmt"
	"net/http"
)

func WithAPIKey(apiKey string) ClientOption {
	return func(c *Client) error {
		if apiKey == "" {
			return fmt.Errorf("no api key provided")
		}

		currentTransport := c.httpClient.Transport
		if currentTransport == nil {
			currentTransport = http.DefaultTransport
		}

		c.httpClient.Transport = &authHeaderTransport{
			name:      "X-Api-Key",
			value:     apiKey,
			transport: currentTransport,
		}

		return nil
	}
}

func WithBearerToken(token string) ClientOption {
	return func(c *Client) error {
		if token == "" {
			return fmt.Errorf("no token provided")
		}

		currentTransport := c.httpClient.Transport
		if currentTransport == nil {
			currentTransport = http.DefaultTransport
		}

		c.httpClient.Transport = &authHeaderTransport{
			name:      "Authorization",
			value:     fmt.Sprintf("Bearer %s", token),
			transport: currentTransport,
		}

		return nil
	}
}

const contextKeyNoAuth contextKey = "noauth"

func withoutAuth() requestOption {
	return func(r *http.Request) error {
		ctx := context.WithValue(r.Context(), contextKeyNoAuth, true)
		*r = *(r.WithContext(ctx))
		return nil
	}
}

type authHeaderTransport struct {
	name      string
	value     string
	transport http.RoundTripper
}

func (t authHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	unauthenticated, ok := req.Context().Value(contextKeyNoAuth).(bool)
	if ok && unauthenticated {
		return t.transport.RoundTrip(req)
	}

	reqCopy := *req // Shallow copy of req

	// Deep copy of request headers, because we'll modify them
	reqCopy.Header = make(http.Header, len(req.Header))
	for hn, hv := range req.Header {
		reqCopy.Header[hn] = append([]string(nil), hv...)
	}

	reqCopy.Header.Set(t.name, t.value)

	return t.transport.RoundTrip(&reqCopy)
}
