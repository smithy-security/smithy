package reader

import (
	"context"
	"io"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"
)

const (
	// Byte represents what the name suggests
	Byte = 1
	// KiB is one kilobyte of data
	KiB = 1024 * Byte
	// MiB is one megabyte of data
	MiB = 1024 * KiB
)

// Safe high end of average files size.
const maxSize = 10 * MiB

// CloseReader is a utility to close a read closer and handle its error.
func CloseReader(ctx context.Context, reader io.ReadCloser) {
	if err := reader.Close(); err != nil {
		logger.LoggerFromContext(ctx).Error(
			"could not close reader",
			slog.String("err", err.Error()),
		)
	}
}

// SafeCopy safely copies with a limit on size of the reader.
// Avoids G111 reported by https://github.com/securego/gosec#usage.
func SafeCopy(ctx context.Context, writer io.Writer, reader io.Reader) error {
	slogger := logger.LoggerFromContext(ctx)

	for {
		n, err := io.Copy(writer, io.LimitReader(reader, maxSize))
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.Errorf("could not copy data to writer: %w", err)
		} else if n > 0 {
			slogger.Debug("copied page of bytes", slog.Int64("bytes_num", n))
			continue
		}

		slogger.Debug("finished copying bytes", slog.Int64("bytes_num", n))
		return nil
	}
}
