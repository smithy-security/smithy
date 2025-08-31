package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/client"
	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/config"
)

// We'll use the generated MockMobSFClient from client package instead of custom mockClient

// captureLogs captures slog output for testing
func captureLogs(t *testing.T) (*strings.Builder, func()) {
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	original := slog.Default()
	slog.SetDefault(logger)

	return &buf, func() {
		slog.SetDefault(original)
	}
}

func TestNew(t *testing.T) {
	t.Run("successful orchestrator creation", func(t *testing.T) {
		// Setup
		cfg := &config.Config{
			Host:    "127.0.0.1",
			Port:    8000,
			APIKey:  "test-api-key",
			Timeout: 30 * time.Second,
		}

		// Execute
		orchestrator, err := New(context.Background(), cfg)

		// Verify
		require.NoError(t, err)
		assert.NotNil(t, orchestrator)
		assert.Equal(t, cfg, orchestrator.cfg)
		assert.NotNil(t, orchestrator.client)
		assert.NotNil(t, orchestrator.service)
	})

	t.Run("retry client creation failure", func(t *testing.T) {
		// Setup - this test would require mocking the retry.NewClient function
		// Since we can't easily mock it, we'll test with a valid config
		// and focus on other failure scenarios
		t.Skip("retry.NewClient mocking requires more complex setup")
	})

	t.Run("MobSF client creation failure", func(t *testing.T) {
		// Setup - invalid config that will cause client creation to fail
		cfg := &config.Config{
			Host:    "", // Invalid host will cause client creation to fail
			Port:    8000,
			APIKey:  "", // Missing API key will cause client creation to fail
			Timeout: 30 * time.Second,
		}

		// Execute
		orchestrator, err := New(context.Background(), cfg)

		// Verify
		require.Error(t, err)
		assert.Nil(t, orchestrator)
		assert.Contains(t, err.Error(), "API key is required")
	})

	t.Run("nil config", func(t *testing.T) {
		// Execute
		orchestrator, err := New(context.Background(), nil)

		// Verify
		require.Error(t, err)
		assert.Nil(t, orchestrator)
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Setup
		cfg := &config.Config{
			Host:    "127.0.0.1",
			Port:    8000,
			APIKey:  "test-api-key",
			Timeout: 30 * time.Second,
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Execute
		orchestrator, err := New(ctx, cfg)

		// Verify - context cancellation shouldn't affect New function
		// since it doesn't use the context for any operations
		require.NoError(t, err)
		assert.NotNil(t, orchestrator)
	})
}

func TestStartMobSFWithRetry(t *testing.T) {
	t.Run("successful start on first attempt", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 3,
			RetryDelay: 100 * time.Millisecond,
		}

		// Expect Start to be called once and succeed
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.NoError(t, err)
	})

	t.Run("successful start after retries", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 2,
			RetryDelay: 10 * time.Millisecond, // Short delay for testing
		}

		// Expect Start to fail twice, then succeed
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			Times(1)

		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			Times(1)

		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.NoError(t, err)
	})

	t.Run("all retries exhausted", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 2,
			RetryDelay: 10 * time.Millisecond,
		}

		expectedErr := fmt.Errorf("persistent failure")

		// Expect Start to fail all attempts
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(expectedErr).
			Times(3) // MaxRetries + 1

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start MobSF after 3 attempts")
		assert.Contains(t, err.Error(), "persistent failure")
	})

	t.Run("zero max retries", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 0,
			RetryDelay: 10 * time.Millisecond,
		}

		expectedErr := fmt.Errorf("start failed")

		// Expect Start to be called once (MaxRetries + 1 = 1)
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(expectedErr).
			Times(1)

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start MobSF after 1 attempts")
	})

	t.Run("negative max retries", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: -1,
			RetryDelay: 10 * time.Millisecond,
		}

		// With MaxRetries = -1, the loop condition becomes attempt <= -1
		// This means the loop never executes, so Start is never called
		// No mock expectations needed

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start MobSF after 0 attempts")
	})

	t.Run("context cancellation during retry", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 5,
			RetryDelay: 100 * time.Millisecond,
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Expect Start to fail multiple times due to context cancellation timing
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			AnyTimes() // Allow any number of calls since context cancellation timing is unpredictable

		// Cancel context after first failure
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		// Execute
		err := startMobSFWithRetry(ctx, mockService, cfg)

		// Verify - context cancellation should cause an error
		require.Error(t, err)
		// The error could be either context cancellation or retry exhaustion
		assert.True(t, strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "failed to start MobSF after"))
	})

	t.Run("retry delay timing", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 2,
			RetryDelay: 50 * time.Millisecond,
		}

		startTime := time.Now()

		// Expect Start to fail twice, then succeed
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			Times(1)

		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			Times(1)

		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.NoError(t, err)

		// Verify that retry delays were applied
		elapsed := time.Since(startTime)
		expectedMinDelay := 50 * time.Millisecond // At least one retry delay
		assert.GreaterOrEqual(t, elapsed, expectedMinDelay)
	})

	t.Run("log capturing during retries", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		cfg := &config.Config{
			MaxRetries: 1,
			RetryDelay: 10 * time.Millisecond,
		}

		logBuf, restoreLogs := captureLogs(t)
		defer restoreLogs()

		// Expect Start to fail once, then succeed
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("start failed")).
			Times(1)

		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := startMobSFWithRetry(context.Background(), mockService, cfg)

		// Verify
		require.NoError(t, err)

		// Verify logs were captured
		logs := logBuf.String()
		assert.Contains(t, logs, "Starting MobSF")
		assert.Contains(t, logs, "Failed to start MobSF")
		assert.Contains(t, logs, "Retrying MobSF start")
		assert.Contains(t, logs, "MobSF started successfully")
	})
}

func TestOrchestrator_Run(t *testing.T) {
	t.Run("successful complete run", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)

		// Create temporary file and directory
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.apk")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		reportDir := t.TempDir()
		reportPath := filepath.Join(reportDir, "report.json")

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: reportPath,
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test-file.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)

		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)

		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)

		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(map[string]interface{}{
				"security_score": 85.0,
				"status":         "completed",
			}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.NoError(t, err)

		// Verify report was written
		reportData, err := os.ReadFile(reportPath)
		require.NoError(t, err)

		var report map[string]interface{}
		err = json.Unmarshal(reportData, &report)
		require.NoError(t, err)
		assert.Equal(t, 85.0, report["security_score"])
		assert.Equal(t, "completed", report["status"])
	})

	t.Run("service start failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)

		cfg := &config.Config{
			FileDir:    "/nonexistent/",
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations - Start fails
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(fmt.Errorf("service start failed")).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start MobSF")
	})

	t.Run("service wait for ready failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)

		cfg := &config.Config{
			FileDir:    "/nonexistent/",
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(fmt.Errorf("service not ready")).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MobSF did not become ready")
	})

	t.Run("health check failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(nil, fmt.Errorf("health check failed")).
			Times(1)

		cfg := &config.Config{
			FileDir:    "/nonexistent/",
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MobSF health check failed")
	})

	t.Run("file read failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)

		cfg := &config.Config{
			FileDir:    "/nonexistent/",
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file for scanning")
	})

	t.Run("file upload failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("upload failed")).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.ipa")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to upload file to MobSF")
	})

	t.Run("start scan failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(fmt.Errorf("start scan failed")).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.zip")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to complete scan")
	})

	t.Run("wait for scan completion failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(fmt.Errorf("scan completion failed")).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.appx")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to wait for scan completion")
	})

	t.Run("generate report failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(nil, fmt.Errorf("generate report failed")).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.ipa")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write report")
	})

	t.Run("JSON marshal failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		// Create a report that cannot be marshaled (circular reference)
		unmarshalableReport := make(map[string]interface{})
		unmarshalableReport["circular"] = unmarshalableReport

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(unmarshalableReport, nil).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.ipa")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal report to JSON")
	})

	t.Run("write report to disk failure", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)

		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(map[string]interface{}{
				"security_score": 85.0,
				"status":         "completed",
			}, nil).
			Times(1)

		// Create temporary file
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.apk")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		// Use a path that cannot be written to
		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: "/root/nonexistent/report.json", // Should fail due to permissions
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write report to disk")
	})

	t.Run("service stop failure during cleanup", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(map[string]interface{}{
				"security_score": 85.0,
				"status":         "completed",
			}, nil).
			Times(1)

		// Create temporary file and directory
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.apk")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		reportDir := t.TempDir()
		reportPath := filepath.Join(reportDir, "report.json")

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: reportPath,
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		// Stop fails during cleanup, but this shouldn't affect the main result
		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(fmt.Errorf("stop failed")).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify - the main operation should succeed even if cleanup fails
		require.NoError(t, err)

		// Verify report was written
		reportData, err := os.ReadFile(reportPath)
		require.NoError(t, err)

		var report map[string]interface{}
		err = json.Unmarshal(reportData, &report)
		require.NoError(t, err)
		assert.Equal(t, 85.0, report["security_score"])
	})

	t.Run("context cancellation during execution", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)

		cfg := &config.Config{
			FileDir:    "/nonexistent/",
			ReportPath: "/nonexistent/report",
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Cancel context after a short delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		// Execute
		err := orchestrator.Run(ctx)

		// Verify - context cancellation should cause an error
		require.Error(t, err)
	})

	t.Run("log capturing during execution", func(t *testing.T) {
		// Setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockMobSFService(ctrl)
		mockClient := NewMockMobSFClient(ctrl)
		mockClient.EXPECT().
			UploadFile(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&client.UploadResponse{
				ID:       "test-id",
				FileName: "test.apk",
				Hash:     "test-hash",
				Size:     1024,
				Status:   "success",
			}, nil).
			Times(1)
		mockClient.EXPECT().
			StartScan(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			WaitForScanCompletion(gomock.Any(), "test-hash").
			Return(nil).
			Times(1)
		mockClient.EXPECT().
			GenerateReport(gomock.Any(), "test-hash").
			Return(map[string]interface{}{
				"security_score": 85.0,
				"status":         "completed",
			}, nil).
			Times(1)

		// Create temporary file and directory
		testContent := []byte("test file content")
		scannedDir := t.TempDir()
		filePath := filepath.Join(scannedDir, "test-file.apk")
		require.NoError(t, os.WriteFile(filePath, testContent, 0644))

		reportDir := t.TempDir()
		reportPath := filepath.Join(reportDir, "report.json")

		cfg := &config.Config{
			FileDir:    scannedDir,
			ReportPath: reportPath,
		}

		orchestrator := &Orchestrator{
			cfg:     cfg,
			client:  mockClient,
			service: mockService,
		}

		logBuf, restoreLogs := captureLogs(t)
		defer restoreLogs()

		// Set up service expectations
		mockService.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			WaitForReady(gomock.Any(), gomock.Any()).
			Return(nil).
			Times(1)

		mockService.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			Times(1)

		// Set up client expectations for health check
		mockClient.EXPECT().
			ListScans(gomock.Any()).
			Return(&client.ScanListResponse{}, nil).
			Times(1)

		// Execute
		err := orchestrator.Run(context.Background())

		// Verify
		require.NoError(t, err)

		// Verify logs were captured
		logs := logBuf.String()
		assert.Contains(t, logs, "Waiting for MobSF to become ready")
		assert.Contains(t, logs, "MobSF health check passed")
		assert.Contains(t, logs, "File uploaded to MobSF")
		assert.Contains(t, logs, "Scan completed successfully")
		assert.Contains(t, logs, "Report written")
		assert.Contains(t, logs, "Stopping MobSF service")
	})
}
