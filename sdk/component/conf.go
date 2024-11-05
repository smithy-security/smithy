package component

import (
	"fmt"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk"
	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
)

const (
	// Err reasons.
	errReasonCannotBeEmpty    = "cannot be empty"
	errReasonUnsupportedValue = "unsupported value"
	errReasonCannotBeNil      = "cannot be nil"

	// Env vars.
	// -- BASE
	envVarKeyComponentName = "SMITHY_COMPONENT_NAME"
	envVarKeyInstanceID    = "SMITHY_INSTANCE_ID"
	// -- LOGGING
	envVarKeyLoggingLogLevel = "SMITHY_LOG_LEVEL"
	// -- STORE
	envVarKeyBackendStoreType = "SMITHY_BACKEND_STORE_TYPE"
	envVarKeyBackendStoreDSN  = "SMITHY_BACKEND_STORE_DSN"
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

		storerConfig runnerConfigStorer
	}

	// RunnerConfigLogging contains the configuration related with the runner logger.
	RunnerConfigLogging struct {
		Level  RunnerConfigLoggingLevel
		Logger Logger
	}

	runnerConfigStorer struct {
		storeType storeType
		dbDSN     string
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
	case rc.storerConfig.store == nil:
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
		r.config.storerConfig.store = store
		r.config.storerConfig.storeType = StoreTypeLocal
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

	componentName, err := fromEnvOrDefault(envVarKeyComponentName, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyComponentName, err)
	}

	instanceIDStr, err := fromEnvOrDefault(envVarKeyInstanceID, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyInstanceID, err)
	}

	instanceID, err := uuid.Parse(instanceIDStr)
	if err != nil {
		return nil, errors.Errorf("could not parse instance ID '%s': %w", instanceIDStr, err)
	}
	// --- END - BASIC ENV - END ---

	// --- BEGIN - LOGGING ENV - BEGIN ---
	logLevel, err := fromEnvOrDefault(
		envVarKeyLoggingLogLevel,
		RunnerConfigLoggingLevelDebug.String(),
		withFallbackToDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyLoggingLogLevel, err)
	}

	logger, err := newDefaultLogger(RunnerConfigLoggingLevel(logLevel))
	if err != nil {
		return nil, errors.Errorf("could not initialised default logger for '%s': %w", envVarKeyLoggingLogLevel, err)
	}
	// --- END - LOGGING ENV - END ---

	// --- BEGIN - STORER ENV - BEGIN ---
	st, err := fromEnvOrDefault(envVarKeyBackendStoreType, "", withFallbackToDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyBackendStoreType, err)
	}

	conf := &RunnerConfig{
		ComponentName: componentName,
		SDKVersion:    sdk.Version,
		InstanceID:    instanceID,
		Logging: RunnerConfigLogging{
			Level:  RunnerConfigLoggingLevel(logLevel),
			Logger: logger,
		},
		PanicHandler: panicHandler,
	}

	if st != "" {
		var storageType = storeType(st)
		if !isAllowedStoreType(storageType) {
			return nil, errors.Errorf("invalid store type for '%s': %w", envVarKeyBackendStoreType, err)
		}

		conf.storerConfig.storeType = storageType

		dbDSN, err := fromEnvOrDefault(
			envVarKeyBackendStoreDSN,
			"smithy.db",
			withFallbackToDefaultOnError(true),
		)
		if err != nil {
			return nil, errors.Errorf("could not lookup environment for '%s': %w", envVarKeyBackendStoreDSN, err)
		}

		conf.storerConfig.dbDSN = dbDSN
		conf.storerConfig.store, err = newStorer(conf.storerConfig)
		if err != nil {
			return nil, errors.Errorf("could not initialise store for '%s': %w", envVarKeyBackendStoreType, err)
		}
	}
	// --- END - STORER ENV - END ---

	return conf, nil
}
