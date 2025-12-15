package transformer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSnykTransformer_Transform tests the Transform method of the snykTransformer.
func TestSnykTransformer_Transform(t *testing.T) {
	// Mock HTTP server to simulate Dependency Track API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate the incoming request
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/bom") {
			// Simulate a successful BOM upload
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"mock-token"}`))
			return
		} else if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/about") {
			// Simulate a successful connection check
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/version") {
			// Simulate a successful connection check
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"version":"mock-version"}`))
			return
		}
		fmt.Printf("Received request: %s %s", r.Method, r.URL.Path)
		// Return 404 for any other requests
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	require.NoError(t, os.Setenv("DEPENDENCY_TRACK_API_KEY", "asdf"))
	require.NoError(t, os.Setenv("DEPENDENCY_TRACK_API_URL", mockServer.URL))
	require.NoError(t, os.Setenv("DEPENDENCY_TRACK_PROJECT_NAME", "asdf"))
	require.NoError(t, os.Setenv("DEPENDENCY_TRACK_PROJECT_UUID", "asdf"))
	require.NoError(t, os.Setenv("DEPENDENCY_TRACK_PROJECT_VERSION", "asdf"))

	// Happy path test
	t.Run("Happy path - successful transform", func(t *testing.T) {
		// Create a temporary file to simulate the raw output file
		rawOutFilePath := t.TempDir() + "/raw_output.json"
		require.NoError(t, os.WriteFile(rawOutFilePath, []byte(`{"mock": "sbom"}`), 0644))
		require.NoError(t, os.Setenv("RAW_OUT_FILE_PATH", rawOutFilePath))
		defer os.Unsetenv("RAW_OUT_FILE_PATH")

		c, err := dtrack.NewClient(
			mockServer.URL,
			dtrack.WithHttpClient(
				&http.Client{Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				}),
			dtrack.WithDebug(true),
			dtrack.WithAPIKey("asdf"),
		)
		require.NoError(t, err)
		// Create a transformer instance
		transformer, err := New(
			SnykTransformerWithDTClient(c),
		)
		require.NoError(t, err)

		// Set up the transformer with mock data
		transformer.rawOutFilePath = rawOutFilePath
		transformer.apiURL = mockServer.URL
		transformer.apiKey = "mock-api-key"
		transformer.projectName = "mock-project"
		transformer.projectUUID = uuid.New().String()
		transformer.projectVersion = "1.0.0"

		// Call the Transform method
		findings, err := transformer.Transform(context.Background())

		// Assert no errors and validate the response
		assert.NoError(t, err)
		assert.NotNil(t, findings)
	})

	// Error case: raw output file not found
	t.Run("Error case - raw output file not found", func(t *testing.T) {
		require.NoError(t, os.Setenv("RAW_OUT_FILE_PATH", "/nonexistent/file/path"))
		defer os.Unsetenv("RAW_OUT_FILE_PATH")

		transformer, err := New()
		require.NoError(t, err)

		_, err = transformer.Transform(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raw output file '/nonexistent/file/path' not found")
	})

	// Error case: BOM upload failure
	t.Run("Error case - BOM upload failure", func(t *testing.T) {
		// Mock server to simulate BOM upload failure
		mockServerFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/bom") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`"error"`))
				return
			} else if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/version") {
				// Simulate a successful connection check
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"version":"mock-version"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServerFail.Close()

		// Create a temporary file to simulate the raw output file
		rawOutFilePath := t.TempDir() + "/raw_output.json"
		require.NoError(t, os.WriteFile(rawOutFilePath, []byte(`{"mock": "sbom"}`), 0644))
		require.NoError(t, os.Setenv("RAW_OUT_FILE_PATH", rawOutFilePath))
		defer os.Unsetenv("RAW_OUT_FILE_PATH")
		c, err := dtrack.NewClient(
			mockServerFail.URL,
			dtrack.WithHttpClient(
				&http.Client{Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				}),
			dtrack.WithDebug(true),
			dtrack.WithAPIKey("asdf"),
		)
		require.NoError(t, err)
		// Create a transformer instance
		transformer, err := New(
			SnykTransformerWithDTClient(c),
		)
		require.NoError(t, err)

		transformer.rawOutFilePath = rawOutFilePath
		transformer.apiURL = mockServerFail.URL
		transformer.apiKey = "mock-api-key"
		transformer.projectName = "mock-project"
		transformer.projectUUID = uuid.New().String()
		transformer.projectVersion = "1.0.0"

		_, err = transformer.Transform(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not upload bom to dependency track")
	})
}
