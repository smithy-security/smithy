package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransport implements http.RoundTripper for testing
type mockTransport struct {
	requests     []*http.Request
	responses    map[string][]*http.Response // Change to slice of responses
	errors       map[string]error
	lastResponse map[string]*http.Response // Keep track of last response for each path
	lastBody     map[string]string         // Keep track of last body content for each path
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	// Check for errors first
	if err, exists := m.errors[req.URL.Path]; exists {
		return nil, err
	}

	// Return mocked response from queue
	if responses, exists := m.responses[req.URL.Path]; exists && len(responses) > 0 {
		// Pop the first response from the queue
		resp := responses[0]
		m.responses[req.URL.Path] = responses[1:] // Remove the used response
		// Store this as the last response
		if m.lastResponse == nil {
			m.lastResponse = make(map[string]*http.Response)
		}
		m.lastResponse[req.URL.Path] = resp
		return resp, nil
	}

	// If no more responses in queue, return the last response instead of 404
	if lastResp, exists := m.lastResponse[req.URL.Path]; exists {
		// Create a new response with the same content to avoid body consumption issues
		bodyContent := m.lastBody[req.URL.Path]
		newResp := &http.Response{
			StatusCode: lastResp.StatusCode,
			Body:       io.NopCloser(strings.NewReader(bodyContent)),
			Header:     lastResp.Header,
		}
		return newResp, nil
	}

	// Default 404 response only if no responses were ever added
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
	}, nil
}

func (m *mockTransport) addResponse(path string, statusCode int, body string, headers map[string]string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}

	for k, v := range headers {
		resp.Header.Set(k, v)
	}

	if m.responses == nil {
		m.responses = make(map[string][]*http.Response)
	}
	if m.lastResponse == nil {
		m.lastResponse = make(map[string]*http.Response)
	}
	if m.lastBody == nil {
		m.lastBody = make(map[string]string)
	}
	m.responses[path] = append(m.responses[path], resp) // Append to slice
	m.lastResponse[path] = resp                         // Store as last response
	m.lastBody[path] = body                             // Store body content
}

func (m *mockTransport) addError(path string, err error) {
	if m.errors == nil {
		m.errors = make(map[string]error)
	}
	m.errors[path] = err
}

func TestNew(t *testing.T) {
	t.Run("successful creation with all options", func(t *testing.T) {
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTimeout(10*time.Second),
		)

		require.NoError(t, err)
		assert.Equal(t, "http://localhost:8000", client.baseURL)
		assert.Equal(t, "test-api-key", client.apiKey)
		assert.Equal(t, 10*time.Second, client.httpClient.Timeout)
	})

	t.Run("missing base URL", func(t *testing.T) {
		client, err := New(WithAPIKey("test-api-key"))

		require.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "base URL is required")
	})

	t.Run("missing API key", func(t *testing.T) {
		client, err := New(WithBaseURL("http://localhost:8000"))

		require.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "API key is required")
	})

}

func TestMobSFClient_ListScans(t *testing.T) {
	t.Run("successful list scans", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
			WithBackoff(1*time.Millisecond),
			WithMaxBackoff(10*time.Millisecond),
		)
		require.NoError(t, err)

		expectedResponse := ScanListResponse{
			Content: []Content{
				{
					Analyzer:    "static_analyzer",
					ScanType:    "apk",
					FileName:    "test.apk",
					AppName:     "TestApp",
					PackageName: "com.test.app",
					VersionName: "1.0.0",
					MD5:         "test-hash",
					Timestamp:   time.Now(),
					ScanLogs:    "test logs",
				},
			},
			Count:    1,
			NumPages: 1,
		}

		responseBody, _ := json.Marshal(expectedResponse)
		transport.addResponse("/api/v1/scans", http.StatusOK, string(responseBody), nil)

		// Execute
		result, err := client.ListScans(context.Background())

		// Verify
		require.NoError(t, err)
		assert.Len(t, result.Content, 1)
		assert.Equal(t, expectedResponse.Content[0].MD5, result.Content[0].MD5)

		// Verify request
		require.Len(t, transport.requests, 1)
		req := transport.requests[0]
		assert.Equal(t, "GET", req.Method)
		assert.Equal(t, "test-api-key", req.Header.Get("Authorization"))
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	})

	t.Run("HTTP request failure", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
			WithBackoff(1*time.Millisecond),
			WithMaxBackoff(10*time.Millisecond),
		)
		require.NoError(t, err)

		transport.addError("/api/v1/scans", fmt.Errorf("network error"))

		// Execute
		result, err := client.ListScans(context.Background())

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "network error")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
			WithBackoff(1*time.Millisecond),
			WithMaxBackoff(10*time.Millisecond),
		)
		require.NoError(t, err)

		transport.addResponse("/api/v1/scans", http.StatusOK, "invalid json", nil)

		// Execute
		result, err := client.ListScans(context.Background())

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to decode response body")
	})
}

func TestMobSFClient_UploadFile(t *testing.T) {
	t.Run("successful file upload", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		fileName := "test.apk"
		fileData := []byte("test file content")

		expectedResponse := UploadResponse{
			ID:       "123",
			FileName: fileName,
			Hash:     "test-hash",
			Size:     int64(len(fileData)),
			Status:   "success",
		}

		responseBody, _ := json.Marshal(expectedResponse)
		transport.addResponse("/api/v1/upload", http.StatusOK, string(responseBody), nil)

		// Execute
		result, err := client.UploadFile(context.Background(), fileName, fileData)

		// Verify
		require.NoError(t, err)
		assert.Equal(t, expectedResponse.ID, result.ID)
		assert.Equal(t, expectedResponse.FileName, result.FileName)
		assert.Equal(t, expectedResponse.Hash, result.Hash)
		assert.Equal(t, expectedResponse.Size, result.Size)
		assert.Equal(t, expectedResponse.Status, result.Status)

		// Verify request
		require.Len(t, transport.requests, 1)
		req := transport.requests[0]
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "test-api-key", req.Header.Get("Authorization"))
		assert.Contains(t, req.Header.Get("Content-Type"), "multipart/form-data")
	})

	t.Run("upload failure with non-200 status", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addResponse("/api/v1/upload", http.StatusInternalServerError, "server error", nil)

		// Execute
		result, err := client.UploadFile(context.Background(), "test.apk", []byte("test"))

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "upload failed with status 500")
	})

	t.Run("HTTP request failure", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addError("/api/v1/upload", fmt.Errorf("network error"))

		// Execute
		result, err := client.UploadFile(context.Background(), "test.apk", []byte("test"))

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "network error")
	})
}

func TestMobSFClient_StartScan(t *testing.T) {
	t.Run("successful scan start", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		fileHash := "test-hash"
		transport.addResponse("/api/v1/scan", http.StatusOK, "success", nil)

		// Execute
		err = client.StartScan(context.Background(), fileHash)

		// Verify
		require.NoError(t, err)

		// Verify request
		require.Len(t, transport.requests, 1)
		req := transport.requests[0]
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "test-api-key", req.Header.Get("Authorization"))
		assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

		// Verify request body
		body, _ := io.ReadAll(req.Body)
		assert.Equal(t, "hash="+fileHash, string(body))
	})

	t.Run("scan start failure with non-200 status", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addResponse("/api/v1/scan", http.StatusBadRequest, "bad request", nil)

		// Execute
		err = client.StartScan(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start scan, status: 400")
	})

	t.Run("HTTP request failure", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addError("/api/v1/scan", fmt.Errorf("network error"))

		// Execute
		err = client.StartScan(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network error")
	})
}

func TestMobSFClient_GenerateReport(t *testing.T) {
	t.Run("successful report generation", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		hash := "test-hash"
		expectedReport := map[string]string{
			"security_score":  "85.0",
			"vulnerabilities": "CVE-2021-1234",
			"status":          "completed",
		}

		responseBody, _ := json.Marshal(expectedReport)
		transport.addResponse("/api/v1/report_json", http.StatusOK, string(responseBody), nil)

		// Execute
		result, err := client.GenerateReport(context.Background(), hash)

		// Verify
		require.NoError(t, err)
		assert.Equal(t, expectedReport["security_score"], result["security_score"])
		assert.Equal(t, expectedReport["vulnerabilities"], result["vulnerabilities"])
		assert.Equal(t, expectedReport["status"], result["status"])

		// Verify request
		require.Len(t, transport.requests, 1)
		req := transport.requests[0]
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "test-api-key", req.Header.Get("Authorization"))
		assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

		// Verify request body
		body, _ := io.ReadAll(req.Body)
		assert.Equal(t, "hash="+hash, string(body))
	})

	t.Run("report generation failure with non-200 status", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addResponse("/api/v1/report_json", http.StatusNotFound, "not found", nil)

		// Execute
		result, err := client.GenerateReport(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to generate report, status: 404")
	})

	t.Run("HTTP request failure", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addError("/api/v1/report_json", fmt.Errorf("network error"))

		// Execute
		result, err := client.GenerateReport(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "network error")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addResponse("/api/v1/report_json", http.StatusOK, "invalid json", nil)

		// Execute
		result, err := client.GenerateReport(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to decode response body")
	})
}

func TestMobSFClient_WaitForScanCompletion(t *testing.T) {

	t.Run("scan not found", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
			WithBackoff(1*time.Millisecond),
			WithMaxBackoff(10*time.Millisecond),
		)
		require.NoError(t, err)

		scanHash := "test-hash"

		// Response: scan not found (add multiple responses for retry attempts)
		scanNotFound := ScanListResponse{
			Content: []Content{},
		}
		response, _ := json.Marshal(scanNotFound)

		// Add one response - the mockTransport will repeat it indefinitely
		transport.addResponse("/api/v1/scans", http.StatusOK, string(response), nil)

		// Execute with timeout context
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = client.WaitForScanCompletion(ctx, scanHash)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})

	t.Run("list scans error", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
		)
		require.NoError(t, err)

		transport.addError("/api/v1/scans", fmt.Errorf("list scans error"))

		// Execute
		err = client.WaitForScanCompletion(context.Background(), "test-hash")

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "list scans error")
	})

	t.Run("scan completion detected", func(t *testing.T) {
		// Setup
		transport := &mockTransport{}
		client, err := New(
			WithBaseURL("http://localhost:8000"),
			WithAPIKey("test-api-key"),
			WithTransport(transport),
			WithBackoff(1*time.Millisecond),
			WithMaxBackoff(10*time.Millisecond),
		)
		require.NoError(t, err)

		scanHash := "test-hash"

		// First response: scan in progress
		scanInProgress := ScanListResponse{
			Content: []Content{
				{
					MD5:      scanHash,
					ScanLogs: "Scanning in progress...",
				},
			},
		}
		response1, _ := json.Marshal(scanInProgress)

		// Second response: scan completed
		scanCompleted := ScanListResponse{
			Content: []Content{
				{
					MD5:      scanHash,
					ScanLogs: "Saving to Database",
				},
			},
		}
		response2, _ := json.Marshal(scanCompleted)

		transport.addResponse("/api/v1/scans", http.StatusOK, string(response1), nil)
		transport.addResponse("/api/v1/scans", http.StatusOK, string(response2), nil)

		// Execute with timeout context
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = client.WaitForScanCompletion(ctx, scanHash)

		// Verify
		require.NoError(t, err)
		assert.Len(t, transport.requests, 2)
	})

}
