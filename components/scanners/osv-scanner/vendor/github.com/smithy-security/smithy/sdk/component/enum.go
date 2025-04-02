package component

type (
	// RunnerConfigLoggingLevel is used to represent log levels.
	// ENUM(debug, info, error, warn)
	RunnerConfigLoggingLevel string

	// StoreType represents a store type
	// ENUM(sqlite, postgresql, findings-client)
	StoreType string
)
