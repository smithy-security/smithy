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
