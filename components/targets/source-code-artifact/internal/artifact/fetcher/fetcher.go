package fetcher

import (
	"net/http"
)

// Config contains the fetcher configuration.
type (
	// Doer abstracts requests' execution.
	Doer interface {
		Do(*http.Request) (*http.Response, error)
	}
	// Config contains fetcher's config.
	Config struct {
		Region          string
		AuthID          string
		AuthSecret      string
		ArtifactURL     string
		BaseHttpClient  Doer
		ArtifactBaseURL string
		BucketName      string
		KeyName         string
	}
)

// Redact redacts strings.
func Redact(s string) string {
	if len(s) <= 3 {
		return "***"
	}
	return s[:3] + "***"
}
