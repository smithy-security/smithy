package logging

import (
	"context"
	"log/slog"
	"os"
)

type loggerCtxKey string

const loggerKey loggerCtxKey = "logger"

type (
	// Logger exposes an slog.Logger compatible logger contract.
	Logger interface {
		Debug(msg string, keyvals ...any)
		Info(msg string, keyvals ...any)
		Warn(msg string, keyvals ...any)
		Error(msg string, keyvals ...any)
		With(args ...any) Logger
	}

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

// FromContext extracts a structured logger from the context for reusability.
func FromContext(ctx context.Context) Logger {
	logger := ctx.Value(loggerKey)
	if logger == nil {
		return &noopLogger{}
	}
	return logger.(Logger)
}

// ContextWithLogger returns a context with a logger in its values for reusability.
func ContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// NewDefaultLogger returns a new default logger that wraps a slog.Logger.
func NewDefaultLogger(level string) *defaultLogger {
	var logLevel = slog.LevelError
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	}

	return &defaultLogger{
		logger: slog.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{
					Level: logLevel,
				},
			),
		),
	}
}
