package transformer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	)

	defer cancel()
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"
	targetMetadata := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

	t.Run("successful transformation", func(t *testing.T) {
		mockFilePath := "testdata/credo.out.sarif.json"
		transformer, err := New(CredoRawOutFilePath(mockFilePath))
		require.NoError(t, err)

		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)
		assert.NotNil(t, findings)
		assert.Len(t, findings, 8)
	})

	t.Run("file not found", func(t *testing.T) {
		transformer, err := New(CredoRawOutFilePath("nonexistent.sarif.json"))
		require.NoError(t, err)

		_, err = transformer.Transform(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raw output file 'nonexistent.sarif.json' not found")
	})

	t.Run("empty file", func(t *testing.T) {
		mockFilePath := filepath.Join(t.TempDir(), "empty.sarif.json")
		err := os.WriteFile(mockFilePath, []byte(""), 0644)
		require.NoError(t, err)

		transformer, err := New(CredoRawOutFilePath(mockFilePath))
		require.NoError(t, err)

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

		_, err = transformer.Transform(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse raw credo output")
	})
}
