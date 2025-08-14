package common

import (
	"archive/tar"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

// Untar untars the contents of the reader into a destination path.
func Untar(ctx context.Context, tarReader io.Reader, destPath string) error {
	l := logger.LoggerFromContext(ctx)

	tr := tar.NewReader(tarReader)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// just fall through and get the next file or directory to create
		}

		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(destPath, header.Name)
		// check the file type
		switch header.Typeflag {
		// if it's a dir, and it doesn't exist create it
		case tar.TypeDir:
			l.Debug("creating directory", slog.String("directory", target))
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0700); err != nil {
					return err
				}
			}
		// if it's a file create it
		case tar.TypeReg:
			l.Debug("extracting file", slog.String("filename", target))
			fd, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(header.Mode))
			if err != nil {
				return errors.Errorf("could not create file '%s' in order to extract data into it: %w", target, err)
			}

			// copy over contents
			if err := reader.SafeCopy(fd, tr); err != nil {
				reader.CloseReader(ctx, fd)
				return errors.Errorf("could not copy data into file: %w", err)
			}

			reader.CloseReader(ctx, fd)
		}
	}
}
