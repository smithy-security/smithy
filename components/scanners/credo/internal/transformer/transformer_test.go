package transformer

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransform(t *testing.T) {
	t.Run("successful transformation", func(t *testing.T) {
		mockFilePath := "testdata/credo.out.sarif.json"
		transformer, err := New(CredoRawOutFilePath(mockFilePath))
		require.NoError(t, err)

		ctx := context.Background()
		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)
		assert.NotNil(t, findings)
		assert.Len(t, findings, 8)
	})

	t.Run("file not found", func(t *testing.T) {
		transformer, err := New(CredoRawOutFilePath("nonexistent.sarif.json"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = transformer.Transform(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raw output file 'nonexistent.sarif.json' not found")
	})

	t.Run("empty file", func(t *testing.T) {
		mockFilePath := "empty.sarif.json"
		err := os.WriteFile(mockFilePath, []byte(""), 0644)
		require.NoError(t, err)
		defer os.Remove(mockFilePath)

		transformer, err := New(CredoRawOutFilePath(mockFilePath))
		require.NoError(t, err)

		ctx := context.Background()
		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		mockFilePath := "invalid.sarif.json"
		err := os.WriteFile(mockFilePath, []byte("{invalid_json}"), 0644)
		require.NoError(t, err)
		defer os.Remove(mockFilePath)

		transformer, err := New(CredoRawOutFilePath(mockFilePath))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = transformer.Transform(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse raw credo output")
	})
}
