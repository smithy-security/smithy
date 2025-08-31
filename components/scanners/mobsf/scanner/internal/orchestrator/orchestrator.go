package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"

	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/client"
	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/config"
	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/service"
)

type (

	// Orchestrator manages the MobSF scanning process
	Orchestrator struct {
		cfg     *config.Config
		client  client.MobSFClient
		service MobSFService
	}

	// MobSFService defines the interface for MobSF operations
	MobSFService interface {
		Start(ctx context.Context) error
		Stop(ctx context.Context) error
		WaitForReady(ctx context.Context, timeout time.Duration) error
	}
)

// New creates a new Orchestrator instance
func New(ctx context.Context, cfg *config.Config) (*Orchestrator, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	mobsfBaseURL := fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)

	retryConfig, err := retry.NewClient(retry.Config{})
	if err != nil {
		slog.Error("Failed to create retry client", "error", err)
		return nil, err
	}

	mobsfClient, err := client.New(
		client.WithBaseURL(mobsfBaseURL),
		client.WithAPIKey(cfg.APIKey),
		client.WithTimeout(cfg.Timeout),
		client.WithHTTPClient(retryConfig),
		client.WithBackoff(cfg.ScanCompletionBackoff),
		client.WithMaxBackoff(cfg.ScanCompletionMaxBackoff),
	)
	if err != nil {
		slog.Error("Failed to create MobSF client", "error", err)
		return nil, err
	}

	return &Orchestrator{
		cfg:     cfg,
		client:  mobsfClient,
		service: service.New(cfg, mobsfClient),
	}, nil
}

func (o *Orchestrator) Run(ctx context.Context) error {

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		slog.Info("Received shutdown signal", "signal", sig.String())
	}()

	// Start MobSF
	if err := startMobSFWithRetry(ctx, o.service, o.cfg); err != nil {
		return errors.Errorf("failed to start MobSF: %w", err)
	}

	defer func() {
		slog.Info("Stopping MobSF service")
		if err := o.service.Stop(ctx); err != nil {
			slog.Error("Failed to stop MobSF service", "error", err)
		}
	}()

	// Wait for MobSF to be ready
	slog.Info("Waiting for MobSF to become ready", "timeout", o.cfg.StartupTimeout)
	if err := o.service.WaitForReady(ctx, o.cfg.StartupTimeout); err != nil {
		return errors.Errorf("MobSF did not become ready: %w", err)
	}

	// Health check
	if _, err := o.client.ListScans(ctx); err != nil {
		return errors.Errorf("MobSF health check failed: %w", err)
	}
	slog.Info("MobSF health check passed")

	// read dir to scan
	var matches []string
	err := filepath.Walk(o.cfg.FileDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			switch ext {
			case ".apk", ".zip", ".ipa", ".appx":
				matches = append(matches, path)
			}
		}
		return nil
	})
	if err != nil {
		return errors.Errorf("failed to read file for scanning: %w", err)
	}
	if len(matches) == 0 {
		dirContents, _ := os.ReadDir(o.cfg.FileDir)
		return errors.Errorf("no supported file found in directory '%s', dir contents: %v", o.cfg.FileDir, dirContents)
	}

	if len(matches) > 1 {
		return errors.Errorf("multiple supported files found in directory '%s', please ensure only one file is present: %v", o.cfg.FileDir, matches)
	}

	targetFile := matches[0]
	fileData, err := os.ReadFile(targetFile)
	if err != nil {
		return errors.Errorf("failed to read file for scanning: %w", err)
	}

	// Upload file to MobSF
	uploadResp, err := o.client.UploadFile(ctx, filepath.Base(targetFile), fileData)
	if err != nil {
		return errors.Errorf("failed to upload file to MobSF: %w", err)
	}
	slog.Info("File uploaded to MobSF", "hash", uploadResp.Hash, "id", uploadResp.ID, "file_name", uploadResp.FileName)

	// Start scan and wait for completion
	if err := o.client.StartScan(ctx, uploadResp.Hash); err != nil {
		return errors.Errorf("failed to complete scan: %w", err)
	}

	if err := o.client.WaitForScanCompletion(ctx, uploadResp.Hash); err != nil {
		return errors.Errorf("failed to wait for scan completion: %w", err)
	}
	slog.Info("Scan completed successfully", "hash", uploadResp.Hash)

	// Write report
	report, err := o.client.GenerateReport(ctx, uploadResp.Hash)
	if err != nil {
		return errors.Errorf("failed to write report: %w", err)
	}
	// Marshal report to JSON
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return errors.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Write report to disk
	if err := os.WriteFile(o.cfg.ReportPath, reportJSON, 0644); err != nil {
		return errors.Errorf("failed to write report to disk: %w", err)
	}

	slog.Info("Report written", "path", o.cfg.ReportPath)

	return nil
}

// startMobSFWithRetry starts MobSF with retry logic
func startMobSFWithRetry(ctx context.Context, service MobSFService, cfg *config.Config) error {
	var lastErr error

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			slog.Info("Retrying MobSF start", "attempt", attempt, "max_retries", cfg.MaxRetries)
			time.Sleep(cfg.RetryDelay)
		}

		slog.Info("Starting MobSF", "attempt", attempt+1, "max_retries", cfg.MaxRetries+1)

		if err := service.Start(ctx); err != nil {
			lastErr = err
			slog.Error("Failed to start MobSF", "attempt", attempt+1, "error", err)
			continue
		}

		slog.Info("MobSF started successfully", "attempt", attempt+1)
		return nil
	}

	return errors.Errorf("failed to start MobSF after %d attempts: %w", cfg.MaxRetries+1, lastErr)
}
