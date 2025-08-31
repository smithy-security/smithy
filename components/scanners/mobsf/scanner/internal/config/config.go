package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/google/uuid"
)

// Config holds the configuration for MobSF
type Config struct {
	MobSFDir                 string
	APIKey                   string
	Host                     string
	Port                     int
	Timeout                  time.Duration
	MaxRetries               int
	RetryDelay               time.Duration
	StartupTimeout           time.Duration
	FileDir                  string
	ReportPath               string
	LogLevel                 string // debug, info, warn, error
	ScanCompletionBackoff    time.Duration
	ScanCompletionMaxBackoff time.Duration
}

// NewConfig loads and validates configuration with extensive validation
func NewConfig() (*Config, error) {
	// Default configuration
	cfg := &Config{
		MobSFDir:                 getEnvOrDefault("MOBSF_DIR", "/home/mobsf/Mobile-Security-Framework-MobSF"),
		APIKey:                   getEnvOrDefault("MOBSF_API_KEY", uuid.NewString()),
		Host:                     getEnvOrDefault("MOBSF_HOST", "127.0.0.1"),
		Port:                     getEnvAsInt("MOBSF_PORT", 8000),
		Timeout:                  getEnvAsDuration("MOBSF_CLIENT_REQUEST_TIMEOUT", 30*time.Second),
		MaxRetries:               getEnvAsInt("MOBSF_CLIENT_MAX_RETRIES", 3),
		RetryDelay:               getEnvAsDuration("MOBSF_CLIENT_RETRY_DELAY", 5*time.Second),
		StartupTimeout:           getEnvAsDuration("MOBSF_STARTUP_TIMEOUT", 2*time.Minute),
		FileDir:                  getEnvOrDefault("MOBSF_SCANNED_FILE_DIR", ""),
		ReportPath:               getEnvOrDefault("MOBSF_REPORT_OUTPUT_PATH", ""),
		LogLevel:                 getEnvOrDefault("MOBSF_ORCHESTRATOR_LOG_LEVEL", "info"),
		ScanCompletionBackoff:    getEnvAsDuration("MOBSF_SCAN_COMPLETION_BACKOFF", time.Second),
		ScanCompletionMaxBackoff: getEnvAsDuration("MOBSF_SCAN_COMPLETION_MAX_BACKOFF", 300*time.Second),
	}

	// Validate required fields
	if err := validateConfig(cfg); err != nil {
		return nil, errors.Errorf("configuration validation failed: %w", err)
	}

	setupLogging(cfg.LogLevel)

	slog.Debug("Configuration loaded successfully",
		"mobsf_dir", cfg.MobSFDir,
		"host", cfg.Host,
		"port", cfg.Port,
		"timeout", cfg.Timeout,
		"max_retries", cfg.MaxRetries,
		"startup_timeout", cfg.StartupTimeout,
		"loglevel", cfg.LogLevel,
	)

	return cfg, nil
}

// validateConfig performs comprehensive configuration validation
func validateConfig(cfg *Config) error {
	var cfgErrors []string

	// Check required fields
	if cfg.APIKey == "" {
		cfgErrors = append(cfgErrors, "MOBSF_API_KEY environment variable is required")
	}

	if cfg.MobSFDir == "" {
		cfgErrors = append(cfgErrors, "MOBSF_DIR environment variable is required")
	}

	// Validate port range
	if cfg.Port < 1 || cfg.Port > 65535 {
		cfgErrors = append(cfgErrors, fmt.Sprintf("MOBSF_PORT must be between 1 and 65535, got %d", cfg.Port))
	}

	// Validate host format
	if cfg.Host == "" {
		cfgErrors = append(cfgErrors, "MOBSF_HOST environment variable is required")
	}

	// Validate timeouts
	if cfg.Timeout <= 0 {
		cfgErrors = append(cfgErrors, "MOBSF_CLIENT_REQUEST_TIMEOUT must be positive")
	}

	if cfg.StartupTimeout <= 0 {
		cfgErrors = append(cfgErrors, "MOBSF_STARTUP_TIMEOUT must be positive")
	}

	// Validate retry settings
	if cfg.MaxRetries < 0 {
		cfgErrors = append(cfgErrors, "MOBSF_CLIENT_MAX_RETRIES cannot be negative")
	}

	if cfg.RetryDelay < 0 {
		cfgErrors = append(cfgErrors, "MOBSF_CLIENT_RETRY_DELAY cannot be negative")
	}

	if err := validateDirectory(cfg.FileDir); err != nil {
		cfgErrors = append(cfgErrors, fmt.Sprintf("MOBSF_SCANNED_FILE_DIR '%s' does not exist or is not accessible", cfg.FileDir))
	}

	if err := validateDirectory(cfg.MobSFDir); err != nil {
		cfgErrors = append(cfgErrors, fmt.Sprintf("MOBSF_DIR validation failed: %v", err))
	}

	if cfg.ReportPath == "" {
		cfgErrors = append(cfgErrors, "MOBSF_REPORT_OUTPUT_PATH environment variable is required")
	}

	if err := validateDirectory(filepath.Dir(cfg.ReportPath)); err != nil {
		cfgErrors = append(cfgErrors, fmt.Sprintf("MOBSF_REPORT_OUTPUT_PATH '%s' does not exist or is not accessible", cfg.ReportPath))
	}

	if len(cfgErrors) > 0 {
		return errors.Errorf("configuration errors: %s", strings.Join(cfgErrors, "; "))
	}

	return nil
}

// validateDirectory checks if directory exists and is accessible
func validateDirectory(dir string) error {
	if dir == "" {
		return errors.New("directory path is empty")
	}
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return errors.Errorf("failed to resolve directory path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return errors.Errorf("directory does not exist or is not accessible: %w", err)
	}

	if !info.IsDir() {
		return errors.Errorf("path exists but is not a directory: %s", absPath)
	}

	slog.Debug("Directory validation passed", "path", absPath)
	return nil
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets environment variable as integer or returns default value
func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		slog.Warn("Invalid integer value for environment variable, using default", "key", key, "value", value, "default", defaultValue)
	}
	return defaultValue
}

// getEnvAsDuration gets environment variable as duration or returns default value
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		slog.Warn("Invalid duration value for environment variable, using default", "key", key, "value", value, "default", defaultValue)
	}
	return defaultValue
}

// setupLogging configures slog based on environment variables
//
// Environment Variables:
//   - MOBSF_ORCHESTRATOR_LOG_LEVEL: Sets the log level (debug, info, warn, error)
//     Defaults to "info" if not set
func setupLogging(logLevel string) {

	// Default to INFO level
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create a new logger with the specified level
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// Replace the default logger
	slog.SetDefault(logger)

	// Log the current log level
	slog.Info("Logging initialized", "level", level.String())
}
