package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
)

type (
	// MobSFClient defines the interface for MobSF client operations
	MobSFClient interface {
		// ListScans retrieves a list of recent scans
		ListScans(ctx context.Context) (*ScanListResponse, error)

		// UploadFile uploads a file for scanning
		UploadFile(ctx context.Context, fileName string, fileData []byte) (*UploadResponse, error)

		// StartScan starts a scan and streams logs until completion
		StartScan(ctx context.Context, fileHash string) error

		// WaitForScanCompletion waits for a scan to complete
		WaitForScanCompletion(ctx context.Context, scanHash string) error

		// GenerateReport generates a JSON report for a scan by hash
		GenerateReport(ctx context.Context, hash string) (map[string]interface{}, error)
	}

	// MobSFClient represents a client for the MobSF REST API
	MobSFClientImpl struct {
		baseURL    string
		apiKey     string
		httpClient *http.Client
		backoff    time.Duration
		maxBackoff time.Duration
	}

	// ClientOption is a functional option for configuring the client
	ClientOption func(*MobSFClientImpl)
)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *MobSFClientImpl) {
		c.httpClient = client
	}
}

// WithTransport sets a custom transport
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *MobSFClientImpl) {
		if c.httpClient == nil {
			c.httpClient = &http.Client{}
		}
		c.httpClient.Transport = transport
	}
}

// WithTimeout sets HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *MobSFClientImpl) {
		if c.httpClient == nil {
			c.httpClient = &http.Client{}
		}
		c.httpClient.Timeout = timeout
	}
}

// WithBaseURL sets the base URL for the MobSF client
func WithBaseURL(baseURL string) ClientOption {
	return func(c *MobSFClientImpl) {
		c.baseURL = baseURL
	}
}

// WithAPIKey sets the API key for the MobSF client
func WithAPIKey(apiKey string) ClientOption {
	return func(c *MobSFClientImpl) {
		c.apiKey = apiKey
	}
}

// WithBackoff sets the initial backoff duration for retries
func WithBackoff(backoff time.Duration) ClientOption {
	return func(c *MobSFClientImpl) {
		c.backoff = backoff
	}
}

// WithMaxBackoff sets the maximum backoff duration for retries
func WithMaxBackoff(maxBackoff time.Duration) ClientOption {
	return func(c *MobSFClientImpl) {
		c.maxBackoff = maxBackoff
	}
}

// New creates a new MobSF client with functional options
func New(options ...ClientOption) (*MobSFClientImpl, error) {
	client := &MobSFClientImpl{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		backoff:    time.Second,
		maxBackoff: 30 * time.Second,
	}

	// Apply options
	for _, option := range options {
		option(client)
	}

	if client.baseURL == "" {
		return nil, errors.New("base URL is required")
	}
	if client.apiKey == "" {
		return nil, errors.New("API key is required")
	}

	slog.Debug("MobSF client created with logging enabled",
		"base_url", client.baseURL,
	)

	return client, nil
}

// doRequest performs an HTTP request with retry logic
func (c *MobSFClientImpl) doRequest(ctx context.Context, method, endpoint string, body io.Reader, contentType ...string) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, endpoint)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, errors.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", c.apiKey)

	// Use custom content type if provided, otherwise default to JSON
	if len(contentType) > 0 {
		req.Header.Set("Content-Type", contentType[0])
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	slog.Debug("HTTP Request",
		"method", method,
		"url", url,
		"content_type", req.Header.Get("Content-Type"),
	)

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Debug("HTTP Request failed", "error", err)
		return nil, errors.Errorf("request failed: %w", err)
	}

	slog.Debug("HTTP Response",
		"status_code", resp.StatusCode,
		"status", resp.Status,
		"content_type", resp.Header.Get("Content-Type"),
		"content_length", resp.ContentLength,
	)

	// Success
	return resp, nil
}

// decodeResponse decodes JSON response into the target interface
func (c *MobSFClientImpl) decodeResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Errorf("failed to read response body: %w", err)
	}

	slog.Debug("Response body",
		"status_code", resp.StatusCode,
		"content_length", len(body),
		"body", string(body),
	)

	if err := json.Unmarshal(body, target); err != nil {
		return errors.Errorf("failed to decode response body: %s: %w", string(body), err)
	}

	return nil
}

// API Response Types

// Content represents the content of a ScanListResponse field
type Content struct {
	Analyzer    string    `json:"ANALYZER"`
	ScanType    string    `json:"SCAN_TYPE"`
	FileName    string    `json:"FILE_NAME"`
	AppName     string    `json:"APP_NAME"`
	PackageName string    `json:"PACKAGE_NAME"`
	VersionName string    `json:"VERSION_NAME"`
	MD5         string    `json:"MD5"`
	Timestamp   time.Time `json:"TIMESTAMP"`
	ScanLogs    string    `json:"SCAN_LOGS"`
}

// ScanListResponse represents the response from listing scans
type ScanListResponse struct {
	Content  []Content `json:"content"`
	Count    int       `json:"count"` // normally you need pagination here, but since we only have 1 scan, we can ignore it
	NumPages int       `json:"num_pages"`
}

// UploadResponse represents the response from uploading a file
type UploadResponse struct {
	ID       string `json:"id"`
	FileName string `json:"file_name"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Status   string `json:"status"`
}

// WaitForScanCompletion waits for a scan to complete
func (c *MobSFClientImpl) WaitForScanCompletion(ctx context.Context, scanHash string) error {
	slog.Debug("Waiting for scan completion", "scan_hash", scanHash)

	backoff := c.backoff
	maxBackoff := c.maxBackoff

	for {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := c.ListScans(ctx)
		if err != nil {
			return fmt.Errorf("failed to list scans: %w", err)
		}

		// Search for the scan in the list of scans
		scanFound := false
		for _, scan := range result.Content {
			if scan.MD5 == scanHash {
				scanFound = true

				logLower := strings.ToLower(scan.ScanLogs)
				if strings.Contains(logLower, "saving to database") {
					slog.Debug("Scan completed successfully", "scan_hash", scanHash)
					return nil
				}
				break
			}
		}

		// Log current state
		if scanFound {
			slog.Debug("Scan not done yet, retrying",
				"scan_hash", scanHash,
				"backoff", backoff)
		} else {
			slog.Debug("Scan not found in list, retrying",
				"scan_hash", scanHash,
				"backoff", backoff)
		}

		// Sleep with context cancellation check
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Update backoff
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// ListScans retrieves a list of recent scans
func (c *MobSFClientImpl) ListScans(ctx context.Context) (*ScanListResponse, error) {
	slog.Debug("Listing recent scans")

	resp, err := c.doRequest(ctx, "GET", "/api/v1/scans", nil)
	if err != nil {
		return nil, errors.Errorf("failed to list scans: %w", err)
	}

	var result ScanListResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, errors.Errorf("failed to decode scans response: %w", err)
	}

	slog.Debug("Scans listed successfully",
		"count", result.Count,
	)

	return &result, nil
}

// UploadFile uploads a file for scanning
func (c *MobSFClientImpl) UploadFile(ctx context.Context, fileName string, fileData []byte) (*UploadResponse, error) {

	slog.Debug("Uploading file",
		"file_name", fileName,
		"file_size", len(fileData),
	)

	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return nil, errors.Errorf("failed to create form file: %w", err)
	}
	if _, err := part.Write(fileData); err != nil {
		return nil, errors.Errorf("failed to write file data: %w", err)
	}

	writer.Close()

	// Use doRequest with the multipart data and custom content type
	resp, err := c.doRequest(ctx, "POST", "/api/v1/upload", &buf, writer.FormDataContentType())
	if err != nil {
		return nil, errors.Errorf("failed to upload file: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, errors.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Decode response
	var result UploadResponse
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, errors.Errorf("failed to decode upload response: %w", err)
	}

	slog.Debug("File upload completed successfully",
		"file_name", fileName,
		"hash", result.Hash,
		"id", result.ID,
	)

	return &result, nil
}

// StartScan starts a scan and streams logs until completion
func (c *MobSFClientImpl) StartScan(ctx context.Context, fileHash string) error {
	slog.Debug("Starting scan",
		"file_hash", fileHash,
	)

	// Create form-encoded data to match curl command
	formData := fmt.Sprintf("hash=%s", fileHash)

	// Use doRequest with form-encoded data and custom content type
	resp, err := c.doRequest(ctx, "POST", "/api/v1/scan", strings.NewReader(formData), "application/x-www-form-urlencoded")
	if err != nil {
		return errors.Errorf("failed to create scan request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to start scan, status: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GenerateReport generates a JSON report for a scan by hash
func (c *MobSFClientImpl) GenerateReport(ctx context.Context, hash string) (map[string]interface{}, error) {
	slog.Debug("Generating report", "hash", hash)

	// Prepare form data
	formData := fmt.Sprintf("hash=%s", hash)
	body := strings.NewReader(formData)

	resp, err := c.doRequest(ctx, "POST", "/api/v1/report_json", body, "application/x-www-form-urlencoded")
	if err != nil {
		return nil, errors.Errorf("failed to generate report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to generate report, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := c.decodeResponse(resp, &result); err != nil {
		return nil, errors.Errorf("failed to decode report response: %w", err)
	}

	slog.Debug("Report generated successfully", "hash", hash)
	return result, nil
}
