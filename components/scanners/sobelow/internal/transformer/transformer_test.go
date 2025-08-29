package transformer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"github.com/stretchr/testify/require"
)

func TestTransform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
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

	t.Run("empty file", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "empty.sarif.json")
		require.NoError(t, os.WriteFile(tempFile, []byte{}, 0644))

		transformer, err := New(
			SobelowRawOutFilePath(tempFile),
			SobelowTransformerWithClock(clock))
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

		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)

		require.Len(t, findings, 8)
	})

	t.Run("file does not exist", func(t *testing.T) {
		nonExistentFile := "./testdata/nonexistent.sarif.json"
		transformer, err := New(SobelowRawOutFilePath(nonExistentFile))
		require.NoError(t, err)

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

		_, err = transformer.Transform(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse raw sobelow output")
	})
}
