package targz

import (
	"compress/gzip"
	"context"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/common"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

type extractor struct{}

// NewExtractor returns a new extractor.
func NewExtractor() extractor {
	return extractor{}
}

// ExtractArtifact extracts a targz archive in the supplied destination.
func (e extractor) ExtractArtifact(ctx context.Context, sourcePath, destPath string) error {
	tmpArchive, err := os.OpenFile(sourcePath, os.O_RDONLY, 0600)
	if err != nil {
		return errors.Errorf("could not open temporary archive file for extracting: %w", err)
	}
	defer reader.CloseReader(ctx, tmpArchive)

	gzr, err := gzip.NewReader(tmpArchive)
	if err != nil {
		return errors.Errorf("could not open gzip archive: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			logger.LoggerFromContext(ctx).Error("could not close gzip reader", slog.String("err", err.Error()))
		}
	}()

	return common.Untar(ctx, gzr, destPath)
}
