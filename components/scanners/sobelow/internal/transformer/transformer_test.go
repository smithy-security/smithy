package transformer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransform(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		tempFile := "./testdata/empty.sarif.json"
		require.NoError(t, os.WriteFile(tempFile, []byte{}, 0644))
		defer func() { require.NoError(t, os.Remove(tempFile)) }()

		transformer, err := New(SobelowRawOutFilePath(tempFile))
		require.NoError(t, err)

		ctx := context.Background()
		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("valid file", func(t *testing.T) {
		testFile := "./testdata/sobelow.sarif.json"
		transformer, err := New(SobelowRawOutFilePath(testFile))
		require.NoError(t, err)

		ctx := context.Background()
		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)

		require.Len(t, findings, 8)
	})

	t.Run("file does not exist", func(t *testing.T) {
		nonExistentFile := "./testdata/nonexistent.sarif.json"
		transformer, err := New(SobelowRawOutFilePath(nonExistentFile))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = transformer.Transform(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("invalid JSON file", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "invalid.sarif.json")
		require.NoError(t, os.WriteFile(tempFile, []byte("invalid json"), 0644))
		defer func() { require.NoError(t, os.Remove(tempFile)) }()

		transformer, err := New(SobelowRawOutFilePath(tempFile))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = transformer.Transform(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse raw sobelow output")
	})
}
