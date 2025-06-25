package reader

import (
	"context"
	"io"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"
)

const (
	Byte = 1
	KiB  = 1024 * Byte
	MiB  = 1024 * KiB
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
func SafeCopy(writer io.Writer, reader io.Reader) error {
	limitedReader := io.LimitReader(reader, maxSize)
	if _, err := io.Copy(writer, limitedReader); err != nil {
		return errors.Errorf("could not copy data to writer: %w. Is the file to big? Max current size is %d MiB.", err, maxSize)
	}
	return nil
}
