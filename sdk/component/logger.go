package component

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

const (
	logKeyError               = "error"
	logKeyPanicStackTrace     = "panic_stack_trace"
	logKeySDKVersion          = "sdk_version"
	logKeyComponentName       = "component_name"
	logKeyWorkflowID          = "workflow_id"
	logKeyComponentType       = "component_type"
	logKeyNumRawFindings      = "num_raw_findings"
	logKeyRawFinding          = "raw_finding"
	logKeyNumParsedFindings   = "num_parsed_findings"
	logKeyNumFilteredFindings = "num_filtered_findings"
	logKeyNumEnrichedFindings = "num_enriched_findings"

	ctxLoggerKey = ctxgKey("logging")
)

type (
	// Logger exposes an slog.Logger compatible logger contract.
	Logger interface {
		Debug(msg string, keyvals ...any)
		Info(msg string, keyvals ...any)
		Warn(msg string, keyvals ...any)
		Error(msg string, keyvals ...any)
		With(args ...any) Logger
	}

	ctxgKey string

	defaultLogger struct {
		logger *slog.Logger
	}

	noopLogger struct{}
)

func (d *defaultLogger) Debug(msg string, keyvals ...any) {
	d.logger.Debug(msg, keyvals...)
}

func (d *defaultLogger) Info(msg string, keyvals ...any) {
	d.logger.Info(msg, keyvals...)
}

func (d *defaultLogger) Warn(msg string, keyvals ...any) {
	d.logger.Warn(msg, keyvals...)
}

func (d *defaultLogger) Error(msg string, keyvals ...any) {
	d.logger.Error(msg, keyvals...)
}

func (d *defaultLogger) With(args ...any) Logger {
	d.logger = d.logger.With(args...)
	return d
}

func (n *noopLogger) Debug(msg string, keyvals ...any) {}
func (n *noopLogger) Info(msg string, keyvals ...any)  {}
func (n *noopLogger) Warn(msg string, keyvals ...any)  {}
func (n *noopLogger) Error(msg string, keyvals ...any) {}
func (n *noopLogger) With(args ...any) Logger {
	return &noopLogger{}
}

// NewNoopLogger can be used to get a NOOP Logger.
func NewNoopLogger() *noopLogger {
	return &noopLogger{}
}

// ContextWithLogger returns a context with a logger in its values for reusability.
func ContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, logger)
}

// LoggerFromContext extracts a structured logger from the context for reusability.
func LoggerFromContext(ctx context.Context) Logger {
	logger := ctx.Value(ctxLoggerKey)
	if logger == nil {
		l, _ := newDefaultLogger(logLevelDebug)
		return l
	}
	return logger.(Logger)
}

func newDefaultLogger(level RunnerConfigLoggingLevel) (*defaultLogger, error) {
	var logLevel slog.Level

	switch level {
	case logLevelDebug:
		logLevel = slog.LevelDebug
	case logLevelInfo:
		logLevel = slog.LevelInfo
	case logLevelError:
		logLevel = slog.LevelError
	case logLevelWarn:
		logLevel = slog.LevelWarn
	default:
		return nil, fmt.Errorf("unknown logger level: %s", level)
	}

	return &defaultLogger{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		})),
	}, nil
}
