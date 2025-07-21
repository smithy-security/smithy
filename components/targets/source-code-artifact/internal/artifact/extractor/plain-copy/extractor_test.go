package plaincopy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	plaincopy "github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/plain-copy"
)

func TestExtractor_ExtractArtifact(t *testing.T) {
	t.Run("it should copy a directory", func(t *testing.T) {
		const (
			sourcePath = "./testdata"
			destPath   = "./moved"
		)

		var (
			ctx, cancel   = context.WithTimeout(context.Background(), time.Second)
			extractor     = plaincopy.NewExtractor()
			movedFilePath = filepath.Join(destPath, "file1.txt")
		)
		defer cancel()

		t.Cleanup(func() {
			require.NoError(
				t,
				os.RemoveAll(destPath),
			)
		})

		require.NoError(t, extractor.ExtractArtifact(ctx, sourcePath, destPath))
		_, err := os.Stat(movedFilePath)
		require.NoError(t, err)
	})
	t.Run("it should copy a file", func(t *testing.T) {
		const (
			sourcePath = "./testdata/file1.txt"
			destPath   = "./moved"
		)

		var (
			ctx, cancel   = context.WithTimeout(context.Background(), time.Second)
			extractor     = plaincopy.NewExtractor()
			movedFilePath = filepath.Join(destPath, "file1.txt")
		)
		defer cancel()

		t.Cleanup(func() {
			require.NoError(
				t,
				os.RemoveAll(destPath),
			)
		})

		require.NoError(t, extractor.ExtractArtifact(ctx, sourcePath, destPath))
		_, err := os.Stat(movedFilePath)
		require.NoError(t, err)
	})
}
