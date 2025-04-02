package component

import (
	"fmt"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/sdk"
	"github.com/smithy-security/smithy/sdk/component/internal/utils"
	"github.com/smithy-security/smithy/sdk/component/uuid"
)

const (
	// Err reasons.
	errReasonCannotBeEmpty = "cannot be empty"
	errReasonCannotBeNil   = "cannot be nil"

	// Env vars.
	// -- BASE
	envVarKeyComponentName = "SMITHY_COMPONENT_NAME"
	envVarKeyInstanceID    = "SMITHY_INSTANCE_ID"
	// -- LOGGING
	envVarKeyLoggingLogLevel = "SMITHY_LOG_LEVEL"
)

type (
	// RunnerConfig is used for centralised runner configuration to be shared between components.
	// This should be extended with all related things with reliability and observability.
	RunnerConfig struct {
		SDKVersion    string
		ComponentName string
		InstanceID    uuid.UUID

		Logging      RunnerConfigLogging
		PanicHandler PanicHandler
		// TODO: add MetricsHandler.
		// TODO: add TracingHandler.

		StoreConfig StoreConfig
	}

	// StoreConfig contains store configuration.
	StoreConfig struct {
		DisableStoreValidation bool
		StoreType              StoreType
		Storer                 Storer
	}

	// RunnerConfigLogging contains the configuration related with the runner logger.
	RunnerConfigLogging struct {
		Level  RunnerConfigLoggingLevel
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
	case rc.InstanceID.IsNil():
		return ErrInvalidRunnerConfig{
			FieldName: "instance_id",
			Reason:    errReasonCannotBeNil,
		}
	case utils.IsNil(rc.Logging.Logger):
		return ErrInvalidRunnerConfig{
			FieldName: "logger",
			Reason:    errReasonCannotBeNil,
		}
	case utils.IsNil(rc.PanicHandler):
		return ErrInvalidRunnerConfig{
			FieldName: "panic_handler",
			Reason:    errReasonCannotBeNil,
		}
	case utils.IsNil(rc.StoreConfig.Storer) && !rc.StoreConfig.DisableStoreValidation:
		return ErrInvalidRunnerConfig{
			FieldName: "store",
			Reason:    errReasonCannotBeNil,
		}
	}

	return nil
}

// runnerWithDisabledStoreCheck is an internal only option which is used to disable store checks for components
// that don't interact with a storage, like targets.
func runnerWithDisabledStoreCheck() RunnerOption {
	return func(r *runner) error {
		r.config.StoreConfig.DisableStoreValidation = true
		return nil
	}
}

// RunnerWithLogger allows customising the runner logger.
func RunnerWithLogger(logger Logger) RunnerOption {
	return func(r *runner) error {
		if utils.IsNil(logger) {
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

// RunnerWithInstanceID allows customising the instance id.
func RunnerWithInstanceID(id uuid.UUID) RunnerOption {
	return func(r *runner) error {
		if id.IsNil() {
			return ErrRunnerOption{
				OptionName: "instance id",
				Reason:     errReasonCannotBeEmpty,
			}
		}
		r.config.InstanceID = id
		return nil
	}
}

// RunnerWithStorer can be used to customise the underlying storage.
func RunnerWithStorer(store Storer) RunnerOption {
	return func(r *runner) error {
		if utils.IsNil(store) {
			return ErrRunnerOption{
				OptionName: "storer",
				Reason:     errReasonCannotBeNil,
			}
		}
		r.config.StoreConfig.Storer = store
		return nil
	}
}

// newRunnerConfig initialises a new RunnerConfig by introspecting the required environment variables
// and applying acceptable defaults.
func newRunnerConfig() (*RunnerConfig, error) {
	// --- BEGIN - BASIC ENV - BEGIN ---
	panicHandler, err := NewDefaultPanicHandler()
	if err != nil {
		return nil, errors.Errorf("could not construct panic handler: %w", err)
	}

	componentName, err := env.GetOrDefault(envVarKeyComponentName, "", env.WithDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyComponentName, err)
	}

	instanceIDStr, err := env.GetOrDefault(envVarKeyInstanceID, "", env.WithDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyInstanceID, err)
	}

	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		return nil, errors.Errorf("could not parse instance ID '%s': %w", instanceIDStr, err)
	}
	// --- END - BASIC ENV - END ---

	// --- BEGIN - LOGGING ENV - BEGIN ---
	logLevel, err := env.GetOrDefault(
		envVarKeyLoggingLogLevel,
		RunnerConfigLoggingLevelDebug.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyLoggingLogLevel, err)
	}

	logger, err := newDefaultLogger(RunnerConfigLoggingLevel(logLevel))
	if err != nil {
		return nil, errors.Errorf("could not initialised default logger for '%s': %w", envVarKeyLoggingLogLevel, err)
	}
	// --- END - LOGGING ENV - END ---

	storeType, err := env.GetOrDefault("SMITHY_STORE_TYPE", StoreTypeSqlite.String(), env.WithDefaultOnError(true))
	if err != nil {
		return nil, err
	}

	return &RunnerConfig{
		ComponentName: componentName,
		SDKVersion:    sdk.Version,
		InstanceID:    instanceID,
		Logging: RunnerConfigLogging{
			Level:  RunnerConfigLoggingLevel(logLevel),
			Logger: logger,
		},
		PanicHandler: panicHandler,
		StoreConfig: StoreConfig{
			StoreType: StoreType(storeType),
		},
	}, nil
}
