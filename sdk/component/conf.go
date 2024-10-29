package component

import (
	"fmt"

	"github.com/smithy-security/smithy/sdk"
)

const (
	logLevelDebug RunnerConfigLoggingLevel = "debug"
	logLevelInfo  RunnerConfigLoggingLevel = "info"
	logLevelError RunnerConfigLoggingLevel = "error"
	logLevelWarn  RunnerConfigLoggingLevel = "warn"

	// Err reasons.
	errReasonCannotBeEmpty    = "cannot be empty"
	errReasonUnsupportedValue = "unsupported value"
	errReasonCannotBeNil      = "cannot be nil"

	// Env vars.
	envVarKeyComponentName   = "SMITHY_COMPONENT_NAME"
	envVarKeyLoggingLogLevel = "SMITHY_LOG_LEVEL"
	envVarKeyBackedStoreType = "SMITHY_BACKEND_STORE_TYPE"
)

type (
	// RunnerConfig is used for centralised runner configuration to be shared between components.
	// This should be extended with all related things with reliability and observability.
	RunnerConfig struct {
		SDKVersion    string
		ComponentName string

		Logging      RunnerConfigLogging
		PanicHandler PanicHandler
		// TODO: add MetricsHandler.
		// TODO: add TracingHandler.

		storerConfig runnerConfigStorer
	}

	// RunnerConfigLoggingLevel is used to represent log levels.
	RunnerConfigLoggingLevel string

	// RunnerConfigLogging contains the configuration related with the runner logger.
	RunnerConfigLogging struct {
		Level RunnerConfigLoggingLevel

		Logger Logger
	}

	runnerConfigStorer struct {
		enabled   bool
		storeType storeType
		store     Storer
	}

	// RunnerConfigOption can be used to override runner configuration defaults.
	// For example overriding the default logger.
	RunnerConfigOption func(*RunnerConfig) error

	// RunnerOption is used to customise the runner if the provided defaults are not enough.
	RunnerOption func(r *runner) error

	// ErrRunnerOption is returned when a supplied RunnerOption is not valid.
	ErrRunnerOption struct {
		OptionName string
		Reason     string
	}

	// ErrInvalidRunnerConfig is returned when a configuration is invalid.
	ErrInvalidRunnerConfig struct {
		FieldName string
		Reason    string
	}
)

func (er ErrRunnerOption) Error() string {
	return fmt.Sprintf("could not apply runner option '%s': %s", er.OptionName, er.Reason)
}

func (er ErrInvalidRunnerConfig) Error() string {
	return fmt.Sprintf("invalid configuration, field '%s': %s", er.FieldName, er.Reason)
}

func (rl RunnerConfigLoggingLevel) String() string {
	return string(rl)
}

func (rc *RunnerConfig) isValid() error {
	switch {
	case rc.SDKVersion == "":
		return ErrInvalidRunnerConfig{
			FieldName: "sdk_version",
			Reason:    errReasonCannotBeEmpty,
		}
	case rc.ComponentName == "":
		return ErrInvalidRunnerConfig{
			FieldName: "component_name",
			Reason:    errReasonCannotBeEmpty,
		}
	case rc.Logging.Logger == nil:
		return ErrInvalidRunnerConfig{
			FieldName: "logger",
			Reason:    errReasonCannotBeNil,
		}
	case rc.PanicHandler == nil:
		return ErrInvalidRunnerConfig{
			FieldName: "panic_handler",
			Reason:    errReasonCannotBeNil,
		}
	case rc.storerConfig.enabled && rc.storerConfig.store == nil:
		return ErrInvalidRunnerConfig{
			FieldName: "store_type",
			Reason:    errReasonCannotBeNil,
		}
	}

	return nil
}

// RunnerWithLogger allows customising the runner logger.
func RunnerWithLogger(logger Logger) RunnerOption {
	return func(r *runner) error {
		if logger == nil {
			return ErrRunnerOption{
				OptionName: "logger",
				Reason:     errReasonCannotBeNil,
			}
		}
		r.config.Logging.Logger = logger
		return nil
	}
}

// RunnerWithComponentName allows customising the component name.
func RunnerWithComponentName(name string) RunnerOption {
	return func(r *runner) error {
		if name == "" {
			return ErrRunnerOption{
				OptionName: "component name",
				Reason:     errReasonCannotBeEmpty,
			}
		}
		r.config.ComponentName = name
		return nil
	}
}

// RunnerWithStorer can be used to customise the underlying storage.
func RunnerWithStorer(stType string, store Storer) RunnerOption {
	return func(r *runner) error {
		switch {
		case !isAllowedStoreType(storeType(stType)):
			return ErrRunnerOption{
				OptionName: "store_type",
				Reason:     errReasonUnsupportedValue,
			}
		case store == nil:
			return ErrRunnerOption{
				OptionName: "storer",
				Reason:     errReasonCannotBeNil,
			}
		}
		r.config.storerConfig.enabled = true
		r.config.storerConfig.store = store
		r.config.storerConfig.storeType = storeTypeLocal
		return nil
	}
}

// newRunnerConfig initialises a new RunnerConfig by introspecting the required environment variables
// and applying acceptable defaults.
func newRunnerConfig() (*RunnerConfig, error) {
	// --- BEGIN - BASIC ENV - BEGIN ---
	panicHandler, err := NewDefaultPanicHandler()
	if err != nil {
		return nil, fmt.Errorf("could not construct panic handler: %w", err)
	}

	componentName, err := fromEnvOrDefault(envVarKeyComponentName, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, fmt.Errorf("could not lookup environment for '%s': %w", envVarKeyComponentName, err)
	}
	// --- END - BASIC ENV - END ---

	// --- BEGIN - LOGGING ENV - BEGIN ---
	logLevel, err := fromEnvOrDefault(envVarKeyLoggingLogLevel, logLevelDebug.String(), withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, fmt.Errorf("could not lookup environment for '%s': %w", envVarKeyLoggingLogLevel, err)
	}

	logger, err := newDefaultLogger(RunnerConfigLoggingLevel(logLevel))
	if err != nil {
		return nil, fmt.Errorf("could not initialised default logger for '%s': %w", envVarKeyLoggingLogLevel, err)
	}
	// --- END - LOGGING ENV - END ---

	// --- BEGIN - STORER ENV - BEGIN ---
	st, err := fromEnvOrDefault(envVarKeyBackedStoreType, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, fmt.Errorf("could not lookup environment for '%s': %w", envVarKeyBackedStoreType, err)
	}

	var (
		storageType         = storeType(st)
		store        Storer = nil
		storeEnabled        = false
	)

	if st != "" {
		if !isAllowedStoreType(storageType) {
			return nil, fmt.Errorf("invalid store type for '%s': %w", envVarKeyBackedStoreType, err)
		}
		store, err = newStorer(storageType)
		if err != nil {
			return nil, fmt.Errorf("could not initialise store for '%s': %w", envVarKeyBackedStoreType, err)
		}
		storeEnabled = true
	}
	// --- END - STORER ENV - END ---

	return &RunnerConfig{
		ComponentName: componentName,
		SDKVersion:    sdk.Version,
		Logging: RunnerConfigLogging{
			Level:  RunnerConfigLoggingLevel(logLevel),
			Logger: logger,
		},
		PanicHandler: panicHandler,
		storerConfig: runnerConfigStorer{
			storeType: storageType,
			store:     store,
			enabled:   storeEnabled,
		},
	}, nil
}
