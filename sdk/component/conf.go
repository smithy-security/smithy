package component

import (
	"fmt"

	"github.com/smithy-security/smithy/sdk"
)

const (
	// Err reasons.
	errReasonCannotBeEmpty = "cannot be empty"
	errReasonCannotBeNil   = "cannot be nil"

	// Env vars.
	envVarKeyComponentName   = "SMITHY_COMPONENT_NAME"
	envVarKeyLoggingLogLevel = "SMITHY_LOGGING_LOG_LEVEL"
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
		// TODO: add ProfilingHandler.
	}

	// RunnerConfigLogging contains the configuration related with the runner logger.
	RunnerConfigLogging struct {
		Level string

		Logger Logger
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

// newRunnerConfig initialises a new RunnerConfig by introspecting the required environment variables
// and applying acceptable defaults.
func newRunnerConfig() (*RunnerConfig, error) {
	panicHandler, err := NewDefaultPanicHandler()
	if err != nil {
		return nil, fmt.Errorf("could not construct panic handler: %w", err)
	}

	componentName, err := fromEnvOrDefault(envVarKeyComponentName, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, fmt.Errorf("could not lookup environment for '%s': %w", envVarKeyComponentName, err)
	}

	logLevel, err := fromEnvOrDefault(envVarKeyLoggingLogLevel, logLevelDebug, withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, fmt.Errorf("could not lookup environment for '%s': %w", envVarKeyLoggingLogLevel, err)
	}

	return &RunnerConfig{
		ComponentName: componentName,
		SDKVersion:    sdk.Version,
		Logging: RunnerConfigLogging{
			Logger: newDefaultLogger(logLevel),
		},
		PanicHandler: panicHandler,
	}, nil
}
