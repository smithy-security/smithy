package service

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/client"
	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/config"
)

// mobsfService implements MobSFService
type mobsfService struct {
	config *config.Config
	cmd    *exec.Cmd
	client client.MobSFClient
}

// New creates a new MobSF service instance
func New(cfg *config.Config, client client.MobSFClient) *mobsfService {
	return &mobsfService{
		config: cfg,
		client: client,
	}
}

// Start starts the MobSF service
func (s *mobsfService) Start(ctx context.Context) error {
	slog.Info("Starting MobSF service", "directory", s.config.MobSFDir)

	// Build the full path to the entrypoint script
	entrypointPath := filepath.Join(s.config.MobSFDir, "scripts", "entrypoint.sh")

	// Validate the entrypoint script exists
	if _, err := os.Stat(entrypointPath); err != nil {
		return errors.Errorf("MobSF entrypoint script not found at %s: %w", entrypointPath, err)
	}

	// Make sure the script is executable
	if err := os.Chmod(entrypointPath, 0755); err != nil {
		slog.Warn("Failed to make entrypoint script executable", "error", err)
	}

	// Create command with proper working directory
	cmd := exec.Command("/bin/bash", entrypointPath)

	// Set environment variables for MobSF
	cmd.Env = append(os.Environ(),
		"MOBSF_API_KEY="+s.config.APIKey,
		"MOBSF_API_ONLY=true",
	)
	cmd.Dir = s.config.MobSFDir

	slog.Info("Equivalent bash command",
		"command", "/bin/bash "+entrypointPath,
		"env", "MOBSF_API_KEY="+s.config.APIKey+" MOBSF_API_ONLY=true",
		"working_dir", cmd.Dir,
	)

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return errors.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return errors.Errorf("failed to start MobSF: %w", err)
	}

	// Store the command for later shutdown
	s.cmd = cmd

	// Stream stdout to go logger in a goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			slog.Info("MobSF stdout", "line", line)
		}
		if err := scanner.Err(); err != nil {
			slog.Error("Error reading MobSF stdout", "error", err)
		}
	}()

	// Stream stderr to go logger in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			slog.Error("MobSF stderr", "line", line)
		}
		if err := scanner.Err(); err != nil {
			slog.Error("Error reading MobSF stderr", "error", err)
		}
	}()

	// Monitor the process in a goroutine
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Error("MobSF process exited with error", "error", err)
		} else {
			slog.Info("MobSF process exited successfully")
		}
	}()

	slog.Info("MobSF service started successfully",
		"directory", s.config.MobSFDir,
		"entrypoint", entrypointPath,
		"pid", cmd.Process.Pid,
	)

	return nil

}

// Stop stops the MobSF service
func (s *mobsfService) Stop(ctx context.Context) error {
	slog.Debug("Stopping MobSF service")

	// Check if not running
	if s.cmd == nil {
		slog.Debug("MobSF service is not running")
		return nil
	}

	// Get the process
	process := s.cmd.Process
	if process == nil {
		slog.Debug("MobSF process is nil")
		s.cmd = nil
		return nil
	}

	// Send SIGTERM for graceful shutdown
	slog.Info("Sending SIGTERM to MobSF process", "pid", process.Pid)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		slog.Warn("Failed to send SIGTERM, trying SIGKILL", "error", err)
		// If SIGTERM fails, try SIGKILL
		if err := process.Kill(); err != nil {
			slog.Error("Failed to kill MobSF process", "error", err)
			return errors.Errorf("failed to kill MobSF process: %w", err)
		}
	}

	// Wait for process to exit with timeout
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			slog.Warn("MobSF process exited with error", "error", err)
		} else {
			slog.Info("MobSF process stopped gracefully")
		}
	case <-time.After(10 * time.Second):
		slog.Warn("MobSF process did not stop gracefully, forcing kill")
		if err := process.Kill(); err != nil {
			slog.Error("Failed to force kill MobSF process", "error", err)
		}
	}

	s.cmd = nil
	slog.Info("MobSF service stop completed")
	return nil
}

// WaitForReady waits for MobSF to be ready
func (s *mobsfService) WaitForReady(ctx context.Context, timeout time.Duration) error {
	slog.Info("Waiting for MobSF ready", "timeout", timeout)

	if timeout <= 0 {
		return errors.Errorf("timeout must be positive")
	}

	// Check if MobSF service is running
	if s.cmd == nil || s.cmd.Process == nil {
		slog.Warn("MobSF service is not running", "cmd", s.cmd)
		return errors.Errorf("MobSF service is not running")
	}

	slog.Info("Waiting for MobSF to be ready...", "timeout", timeout)

	// Create a ticker to check health endpoint
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return errors.Errorf("timeout waiting for MobSF to be ready: %w", timeoutCtx.Err())
		case <-ticker.C:
			// Check if MobSF is ready
			if err := s.checkAPIReady(ctx); err == nil {
				slog.Info("MobSF is ready and responding")
				return nil
			} else {
				slog.Info("MobSF not ready yet", "error", err)
			}
		}
	}
}

// checkAPIReady checks if MobSF is ready
func (s *mobsfService) checkAPIReady(ctx context.Context) error {
	// Check if process is still alive
	if err := s.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return errors.Errorf("MobSF process is not responding: %w", err)
	}

	// Make an API call to list scans to verify MobSF is fully operational
	if _, err := s.client.ListScans(ctx); err != nil {
		return errors.Errorf("MobSF API not responding: %w", err)
	}

	return nil
}
