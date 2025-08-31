package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	t.Run("config creation fails with missing required values", func(t *testing.T) {
		// Setup - clear environment variables to test defaults
		clearEnvVars()

		// Execute
		cfg, err := NewConfig()

		// Verify - should fail because required fields are missing
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "configuration validation failed")

		// Check for specific required field errors
		errMsg := err.Error()
		assert.Contains(t, errMsg, "MOBSF_SCANNED_FILE_DIR")
		assert.Contains(t, errMsg, "MOBSF_REPORT_OUTPUT_PATH")
		assert.Contains(t, errMsg, "does not exist or is not accessible")
	})

	t.Run("successful config creation with all required values", func(t *testing.T) {
		// Setup - create temporary directories and files for valid config
		mobsfDir := t.TempDir()
		reportDir := t.TempDir()
		scannedDir := t.TempDir()
		testFile := filepath.Join(scannedDir, "test.apk")
		require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

		clearEnvVars()
		setEnvVars(map[string]string{
			"MOBSF_DIR":                    mobsfDir,
			"MOBSF_API_KEY":                "custom-api-key",
			"MOBSF_HOST":                   "192.168.1.100",
			"MOBSF_PORT":                   "9000",
			"MOBSF_CLIENT_REQUEST_TIMEOUT": "60s",
			"MOBSF_CLIENT_MAX_RETRIES":     "5",
			"MOBSF_CLIENT_RETRY_DELAY":     "10s",
			"MOBSF_STARTUP_TIMEOUT":        "5m",
			"MOBSF_SCANNED_FILE_DIR":       scannedDir,
			"MOBSF_REPORT_OUTPUT_PATH":     filepath.Join(reportDir, "report.json"),
			"MOBSF_ORCHESTRATOR_LOG_LEVEL": "debug",
		})

		// Execute
		cfg, err := NewConfig()

		// Verify
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, mobsfDir, cfg.MobSFDir)
		assert.Equal(t, "custom-api-key", cfg.APIKey)
		assert.Equal(t, "192.168.1.100", cfg.Host)
		assert.Equal(t, 9000, cfg.Port)
		assert.Equal(t, 60*time.Second, cfg.Timeout)
		assert.Equal(t, 5, cfg.MaxRetries)
		assert.Equal(t, 10*time.Second, cfg.RetryDelay)
		assert.Equal(t, 5*time.Minute, cfg.StartupTimeout)
		assert.Equal(t, scannedDir, cfg.FileDir)
		assert.Equal(t, filepath.Join(reportDir, "report.json"), cfg.ReportPath)
		assert.Equal(t, "debug", cfg.LogLevel)
	})

	t.Run("config creation fails validation", func(t *testing.T) {
		// Setup - set invalid values that will fail validation
		clearEnvVars()
		setEnvVars(map[string]string{
			"MOBSF_PORT": "99999", // Invalid port
		})

		// Execute
		cfg, err := NewConfig()

		// Verify
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "configuration validation failed")
		assert.Contains(t, err.Error(), "MOBSF_PORT must be between 1 and 65535")
	})
}

func TestValidateConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		// Setup - create temporary directories and files for valid config
		mobsfDir := t.TempDir()
		reportDir := t.TempDir()
		scannedDir := t.TempDir()
		testFile := filepath.Join(scannedDir, "test.apk")
		require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

		cfg := &Config{
			MobSFDir:       mobsfDir,
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        scannedDir,
			ReportPath:     filepath.Join(reportDir, "report.json"),
			LogLevel:       "info",
		}

		// Verify
		require.NoError(t, validateConfig(cfg))
	})

	t.Run("missing API key", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "", // Missing API key
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_API_KEY environment variable is required")
	})

	t.Run("missing MobSF directory", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "", // Missing directory
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_DIR environment variable is required")
	})

	t.Run("missing host", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "", // Missing host
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_HOST environment variable is required")
	})

	t.Run("port too low", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           0, // Invalid port
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_PORT must be between 1 and 65535, got 0")
	})

	t.Run("port too high", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           70000, // Invalid port
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_PORT must be between 1 and 65535, got 70000")
	})

	t.Run("zero timeout", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        0, // Invalid timeout
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_CLIENT_REQUEST_TIMEOUT must be positive")
	})

	t.Run("negative timeout", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        -5 * time.Second, // Invalid timeout
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_CLIENT_REQUEST_TIMEOUT must be positive")
	})

	t.Run("zero startup timeout", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 0, // Invalid startup timeout
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_STARTUP_TIMEOUT must be positive")
	})

	t.Run("negative startup timeout", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: -1 * time.Minute, // Invalid startup timeout
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_STARTUP_TIMEOUT must be positive")
	})

	t.Run("negative max retries", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     -1, // Invalid max retries
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_CLIENT_MAX_RETRIES cannot be negative")
	})

	t.Run("negative retry delay", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     -1 * time.Second, // Invalid retry delay
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "/valid/report",
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_CLIENT_RETRY_DELAY cannot be negative")
	})

	t.Run("missing report path", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "/valid/dir",
			APIKey:         "valid-api-key",
			Host:           "127.0.0.1",
			Port:           8000,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			RetryDelay:     5 * time.Second,
			StartupTimeout: 2 * time.Minute,
			FileDir:        "/valid/file",
			ReportPath:     "", // Missing report path
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MOBSF_REPORT_OUTPUT_PATH environment variable is required")
	})

	t.Run("multiple validation errors", func(t *testing.T) {
		// Setup
		cfg := &Config{
			MobSFDir:       "",               // Missing directory
			APIKey:         "",               // Missing API key
			Host:           "",               // Missing host
			Port:           0,                // Invalid port
			Timeout:        0,                // Invalid timeout
			MaxRetries:     -1,               // Invalid max retries
			RetryDelay:     -1 * time.Second, // Invalid retry delay
			StartupTimeout: 0,                // Invalid startup timeout
			FileDir:        "/valid/file",
			ReportPath:     "", // Missing report path
			LogLevel:       "info",
		}

		// Execute
		err := validateConfig(cfg)

		// Verify
		require.Error(t, err)
		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "configuration errors")
		assert.Contains(t, errorMsg, "MOBSF_API_KEY environment variable is required")
		assert.Contains(t, errorMsg, "MOBSF_DIR environment variable is required")
		assert.Contains(t, errorMsg, "MOBSF_HOST environment variable is required")
		assert.Contains(t, errorMsg, "MOBSF_PORT must be between 1 and 65535, got 0")
		assert.Contains(t, errorMsg, "MOBSF_CLIENT_REQUEST_TIMEOUT must be positive")
		assert.Contains(t, errorMsg, "MOBSF_STARTUP_TIMEOUT must be positive")
		assert.Contains(t, errorMsg, "MOBSF_CLIENT_MAX_RETRIES cannot be negative")
		assert.Contains(t, errorMsg, "MOBSF_CLIENT_RETRY_DELAY cannot be negative")
		assert.Contains(t, errorMsg, "MOBSF_REPORT_OUTPUT_PATH environment variable is required")
	})
}

func TestValidateDirectory(t *testing.T) {
	t.Run("valid directory", func(t *testing.T) {
		// Setup - create temporary directory
		tempDir := t.TempDir()

		// Execute
		err := validateDirectory(tempDir)

		// Verify
		require.NoError(t, err)
	})

	t.Run("directory does not exist", func(t *testing.T) {
		// Setup
		nonExistentDir := "/non/existent/directory"

		// Execute
		err := validateDirectory(nonExistentDir)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directory does not exist or is not accessible")
	})

	t.Run("path exists but is not a directory", func(t *testing.T) {
		// Setup - create temporary file
		tempFile := filepath.Join(t.TempDir(), "test.txt")
		err := os.WriteFile(tempFile, []byte("test"), 0644)
		require.NoError(t, err)

		// Execute
		err = validateDirectory(tempFile)

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path exists but is not a directory")
	})

	t.Run("invalid path that cannot be resolved", func(t *testing.T) {
		// Setup - create a path that cannot be resolved to absolute
		// This is tricky to test, but we can try with a very long path
		veryLongPath := string(make([]byte, 4096)) // Very long path

		// Verify - this might fail in different ways depending on the OS
		require.Error(t, validateDirectory(veryLongPath))
	})
}

func TestGetEnvOrDefault(t *testing.T) {
	t.Run("environment variable set", func(t *testing.T) {
		// Setup
		key := "TEST_ENV_VAR"
		expectedValue := "test-value"
		os.Setenv(key, expectedValue)
		defer os.Unsetenv(key)

		// Execute
		result := getEnvOrDefault(key, "default-value")

		// Verify
		assert.Equal(t, expectedValue, result)
	})

	t.Run("environment variable not set", func(t *testing.T) {
		// Setup
		key := "TEST_ENV_VAR_NOT_SET"
		defaultValue := "default-value"

		// Execute
		result := getEnvOrDefault(key, defaultValue)

		// Verify
		assert.Equal(t, defaultValue, result)
	})

	t.Run("environment variable empty string", func(t *testing.T) {
		// Setup
		key := "TEST_ENV_VAR_EMPTY"
		os.Setenv(key, "")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvOrDefault(key, "default-value")

		// Verify
		assert.Equal(t, "default-value", result)
	})
}

func TestGetEnvAsInt(t *testing.T) {
	t.Run("valid integer environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_INT_VAR"
		expectedValue := 42
		os.Setenv(key, "42")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsInt(key, 100)

		// Verify
		assert.Equal(t, expectedValue, result)
	})

	t.Run("environment variable not set", func(t *testing.T) {
		// Setup
		key := "TEST_INT_VAR_NOT_SET"
		defaultValue := 100

		// Execute
		result := getEnvAsInt(key, defaultValue)

		// Verify
		assert.Equal(t, defaultValue, result)
	})

	t.Run("invalid integer environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_INT_VAR_INVALID"
		os.Setenv(key, "not-a-number")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsInt(key, 100)

		// Verify
		assert.Equal(t, 100, result) // Should fall back to default
	})

	t.Run("empty string environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_INT_VAR_EMPTY"
		os.Setenv(key, "")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsInt(key, 100)

		// Verify
		assert.Equal(t, 100, result) // Should fall back to default
	})
}

func TestGetEnvAsDuration(t *testing.T) {
	t.Run("valid duration environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_DURATION_VAR"
		expectedValue := 30 * time.Second
		os.Setenv(key, "30s")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsDuration(key, 60*time.Second)

		// Verify
		assert.Equal(t, expectedValue, result)
	})

	t.Run("environment variable not set", func(t *testing.T) {
		// Setup
		key := "TEST_DURATION_VAR_NOT_SET"
		defaultValue := 60 * time.Second

		// Execute
		result := getEnvAsDuration(key, defaultValue)

		// Verify
		assert.Equal(t, defaultValue, result)
	})

	t.Run("invalid duration environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_DURATION_VAR_INVALID"
		os.Setenv(key, "not-a-duration")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsDuration(key, 60*time.Second)

		// Verify
		assert.Equal(t, 60*time.Second, result) // Should fall back to default
	})

	t.Run("empty string environment variable", func(t *testing.T) {
		// Setup
		key := "TEST_DURATION_VAR_EMPTY"
		os.Setenv(key, "")
		defer os.Unsetenv(key)

		// Execute
		result := getEnvAsDuration(key, 60*time.Second)

		// Verify
		assert.Equal(t, 60*time.Second, result) // Should fall back to default
	})

	t.Run("complex duration formats", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected time.Duration
		}{
			{"1h30m", 1*time.Hour + 30*time.Minute},
			{"2h", 2 * time.Hour},
			{"45m", 45 * time.Minute},
			{"30s", 30 * time.Second},
			{"500ms", 500 * time.Millisecond},
			{"1.5h", 1*time.Hour + 30*time.Minute},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				// Setup
				key := "TEST_DURATION_COMPLEX"
				os.Setenv(key, tc.input)
				defer os.Unsetenv(key)

				// Execute
				result := getEnvAsDuration(key, 60*time.Second)

				// Verify
				assert.Equal(t, tc.expected, result)
			})
		}
	})
}

func TestSetupLogging(t *testing.T) {
	t.Run("debug log level", func(t *testing.T) {
		// Setup
		logLevel := "debug"

		// Execute
		setupLogging(logLevel)

		// Verify - check that logging was set up (this is mostly a smoke test)
		// The actual log level verification would require accessing internal logger state
	})

	t.Run("info log level", func(t *testing.T) {
		// Setup
		logLevel := "info"

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})

	t.Run("warn log level", func(t *testing.T) {
		// Setup
		logLevel := "warn"

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})

	t.Run("warning log level (alias)", func(t *testing.T) {
		// Setup
		logLevel := "warning"

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})

	t.Run("error log level", func(t *testing.T) {
		// Setup
		logLevel := "error"

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})

	t.Run("invalid log level defaults to info", func(t *testing.T) {
		// Setup
		logLevel := "invalid-level"

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})

	t.Run("empty log level defaults to info", func(t *testing.T) {
		// Setup
		logLevel := ""

		// Execute
		setupLogging(logLevel)

		// Verify
		// This is a smoke test since we can't easily verify the internal logger state
	})
}

// Helper functions for test setup and cleanup

func clearEnvVars() {
	envVars := []string{
		"MOBSF_DIR",
		"MOBSF_API_KEY",
		"MOBSF_HOST",
		"MOBSF_PORT",
		"MOBSF_CLIENT_REQUEST_TIMEOUT",
		"MOBSF_CLIENT_MAX_RETRIES",
		"MOBSF_CLIENT_RETRY_DELAY",
		"MOBSF_STARTUP_TIMEOUT",
		"MOBSF_SCANNED_FILE_DIR",
		"MOBSF_REPORT_OUTPUT_PATH",
		"MOBSF_ORCHESTRATOR_LOG_LEVEL",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}
}

func setEnvVars(vars map[string]string) {
	for key, value := range vars {
		os.Setenv(key, value)
	}
}
