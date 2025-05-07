package dtrack

import (
	"fmt"
	"io"
	"net/http"
)

type APIError struct {
	StatusCode int
	Message    string
}

func (e APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("api error (status: %d)", e.StatusCode)
	}
	return fmt.Sprintf("%s (status: %d)", e.Message, e.StatusCode)
}

func checkResponseForError(res *http.Response) error {
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}

	apiErr := &APIError{StatusCode: res.StatusCode}

	body, err := io.ReadAll(res.Body)
	if err == nil && body != nil {
		apiErr.Message = string(body)
	}

	return apiErr
}
