package logging

import (
	"context"
	"log/slog"
	"os"
)

type loggerKey string

const ctxLoggerKey = loggerKey("logging")

// NewLogger returns a new structured logger.
func NewLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// WithContext returns a context with a logger in its values for reusability.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, logger)
}

// FromContext extracts a structured logger from the context for reusability.
func FromContext(ctx context.Context) *slog.Logger {
	logger := ctx.Value(ctxLoggerKey)
	if logger == nil {
		return NewLogger()
	}
	return logger.(*slog.Logger)
}
