package tar_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/tar"
)

func TestExtractor_ExtractArtifact(t *testing.T) {
	const destPath = "./testdata/unpacked"

	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(destPath))
	})

	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		extractor   = tar.NewExtractor()
	)
	defer cancel()

	require.NoError(t, extractor.ExtractArtifact(ctx, "./testdata/test_archive.tar", destPath))
	_, err := os.Stat(filepath.Join(destPath, "test_folder/file1.txt"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(destPath, "test_folder/file2.txt"))
	require.NoError(t, err)
}
