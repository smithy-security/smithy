package component

import (
	"fmt"

	"github.com/smithy-security/smithy/sdk"
)

const (
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
)

func (er ErrRunnerOption) Error() string {
	return fmt.Sprintf("could not apply runner option '%s': %s", er.OptionName, er.Reason)
}

// RunnerWithConfig allows customising the runner configuration.
func RunnerWithConfig(config *RunnerConfig) RunnerOption {
	return func(r *runner) error {
		if config == nil {
			return ErrRunnerOption{
				OptionName: "config",
				Reason:     "cannot be nil",
			}
		}
		r.config = config
		return nil
	}
}

// RunnerWithComponentName allows customising the component name.
func RunnerWithComponentName(name string) RunnerOption {
	return func(r *runner) error {
		if name == "" {
			return ErrRunnerOption{
				OptionName: "component name",
				Reason:     "cannot be empty",
			}
		}
		r.config.ComponentName = name
		return nil
	}
}

// newDefaultRunnerConfig initialises a new RunnerConfig by introspecting the required environment variables
// and applying acceptable defaults.
func newDefaultRunnerConfig() (*RunnerConfig, error) {
	panicHandler, err := NewDefaultPanicHandler()
	if err != nil {
		return nil, fmt.Errorf("could not construct panic handler: %w", err)
	}

	componentName, err := fromEnvOrDefault(envVarKeyComponentName, "")
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
