package zip

import (
	"archive/zip"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

type extractor struct{}

// NewExtractor returns a new extractor.
func NewExtractor() extractor {
	return extractor{}
}

// ExtractArtifact extracts the archive to the destination path using unzip.
func (e extractor) ExtractArtifact(ctx context.Context, sourcePath, destPath string) error {
	l := logger.LoggerFromContext(ctx)

	tmpArchive, err := os.OpenFile(sourcePath, os.O_RDONLY, 0600)
	if err != nil {
		return errors.Errorf("could not open temporary archive file for extracting: %w", err)
	}
	defer reader.CloseReader(ctx, tmpArchive)

	tmpArchiveStat, err := os.Stat(sourcePath)
	if err != nil {
		return errors.Errorf("could not get stat of temp archive file: %w", err)
	}

	zipReader, err := zip.NewReader(tmpArchive, tmpArchiveStat.Size())
	if err != nil {
		return errors.Errorf("there was an issue creating reader for zip archive: %w", err)
	}

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return errors.Errorf("could not create destination directory: %w", err)
	}

	// Extract each file
	for _, file := range zipReader.File {
		path := filepath.Join(destPath, file.Name)

		// Check for ZipSlip vulnerability
		if !strings.HasPrefix(path, filepath.Clean(destPath)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		// Handle directories
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				l.Error("could not create directory", slog.String("err", err.Error()))
			}
			continue
		}

		l.Debug("extracting file", slog.String("filename", path))
		// Make sure directory exists
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return errors.Errorf("could not create directory: %s", filepath.Dir(path))
		}

		// Create the file
		dstFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return errors.Errorf("could not open temporary file for writing: %w", err)
		}

		// Open the file inside the zip
		srcFile, err := file.Open()
		if err != nil {
			if err := dstFile.Close(); err != nil {
				l.Error("could not create directory", slog.String("err", err.Error()))
			}
			return err
		}

		// Copy contents
		if err := reader.SafeCopy(dstFile, srcFile); err != nil {
			return err
		}

		reader.CloseReader(ctx, srcFile)
		reader.CloseReader(ctx, dstFile)
	}

	return nil
}
