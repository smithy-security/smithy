package plaincopy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

type extractor struct{}

// NewExtractor returns a new extractor.
func NewExtractor() extractor {
	return extractor{}
}

// ExtractArtifact copies all contents from source path to destination path.
func (e extractor) ExtractArtifact(ctx context.Context, sourcePath, destPath string) error {
	slogger := logger.
		LoggerFromContext(ctx).
		With(
			slog.String("source_path", sourcePath),
			slog.String("dest_path", destPath),
		)

	info, err := os.Stat(sourcePath)
	if err != nil {
		return errors.Errorf("could not stat source path: %s", sourcePath)
	}

	if err := os.MkdirAll(destPath, 0755); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errors.Errorf("could not create destination directory: %w", err)
		}
	}

	if info.IsDir() {
		slogger.Debug("source path is a directory, moving all of its contents!")
		if err := os.CopyFS(destPath, os.DirFS(sourcePath)); err != nil {
			return errors.Errorf(
				"could not copy source directory '%s' to destination '%s': %w",
				sourcePath,
				destPath,
				err,
			)
		}
		return nil
	}

	slogger.Debug("source path is a file, moving it!")
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return errors.Errorf("failed to open source file '%s': %w", sourcePath, err)
	}
	defer reader.CloseReader(ctx, sourceFile)

	destinationFile, err := os.Create(filepath.Join(destPath, filepath.Base(sourceFile.Name())))
	if err != nil {
		return errors.Errorf(
			"failed to create destination file '%s': %w",
			filepath.Base(sourceFile.Name()),
			err,
		)
	}
	defer reader.CloseReader(ctx, destinationFile)

	if _, err = io.Copy(destinationFile, sourceFile); err != nil {
		return errors.Errorf(
			"failed to copy file '%s' to destination '%s': %w",
			filepath.Base(sourceFile.Name()),
			destPath,
			err,
		)
	}

	if err = destinationFile.Sync(); err != nil {
		return errors.Errorf("failed to sync destination file '%s': %w", destPath, err)
	}

	return nil
}
