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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobSFTransformer_FullReports(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
	)

	defer cancel()
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"
	targetMetadata := &ocsffindinginfo.DataSource{
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}
	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

	t.Run("android: full report", func(t *testing.T) {
		jsonPath := filepath.Join("testdata", "injured-android-apk-scan.json")
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(jsonPath))
		require.NoError(t, err)

		findings, err := tr.Transform(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		for _, f := range findings {
			assert.NotEmpty(t, f.FindingInfo.Title)
			assert.NotEmpty(t, f.FindingInfo.Desc)
			assert.NotNil(t, f.Severity)
		}
	})

	t.Run("ios: full report", func(t *testing.T) {
		jsonPath := filepath.Join("testdata", "dvia-v2-swift-report.json")
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(jsonPath))
		require.NoError(t, err)
		findings, err := tr.Transform(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		for _, f := range findings {
			assert.NotEmpty(t, f.FindingInfo.Title)
			assert.NotEmpty(t, f.FindingInfo.Desc)
			assert.NotNil(t, f.Severity)
		}
	})

	t.Run("error: file not found", func(t *testing.T) {
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(filepath.Join(t.TempDir(), "missing.json")))
		require.NoError(t, err)
		findings, err := tr.Transform(ctx)
		assert.Error(t, err)
		assert.Nil(t, findings)
	})

	t.Run("error: invalid JSON", func(t *testing.T) {
		rawPath := filepath.Join(t.TempDir(), "invalid.json")
		os.WriteFile(rawPath, []byte("not-json"), 0644)
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(rawPath))
		require.NoError(t, err)
		findings, err := tr.Transform(ctx)
		assert.Error(t, err)
		assert.Nil(t, findings)
	})
}
