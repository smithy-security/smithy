package mock

import (
	"net/http"

	"github.com/smithy-security/smithy/pkg/utils"
)

var _ utils.MockableRequestDoer = (*HTTPReqDoer)(nil)

// HTTPReqDoer is a struct that can be used to mock an HTTP request Do method.
type HTTPReqDoer struct {
	Hook func(*http.Request) (*http.Response, error)
}

// Do invokes the internal Hook to perform a call that resembles the http.Do
// function.
func (m *HTTPReqDoer) Do(r *http.Request) (*http.Response, error) {
	return m.Hook(r)
}
