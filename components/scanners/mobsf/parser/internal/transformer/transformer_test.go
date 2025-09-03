package transformer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestMobSFTransformer_FullReports(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
	)

	defer cancel()
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"

	expectedSeverityValues := []ocsf.VulnerabilityFinding_SeverityId{
		ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
		ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
		ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
		ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER,
	}

	t.Run("android: full report", func(t *testing.T) {
		jsonPath := filepath.Join("testdata", "injured-android-apk-scan.json")
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(jsonPath))
		require.NoError(t, err)

		targetMetadata := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "some-release.apk",
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: repositoryURL,
				Reference:     commitRef,
			},
		}
		ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

		findings, err := tr.Transform(ctx)
		require.NoError(t, err)

		require.NotEmpty(t, findings)
		for _, f := range findings {
			assert.NotEmpty(t, f.FindingInfo.Title)
			assert.NotEmpty(t, f.FindingInfo.Desc)
			assert.NotNil(t, f.Severity)
			assert.NotNil(t, f.Severity)
			assert.NotEmpty(t, *f.Severity)
			require.NotEmpty(t, f.FindingInfo.DataSources)
			require.NotEmpty(t, f.FindingInfo.DataSources[0])

			unmarshaledDataSource := &ocsffindinginfo.DataSource{}
			require.NoError(t, protojson.Unmarshal([]byte(f.FindingInfo.DataSources[0]), unmarshaledDataSource))
			assert.Equal(t, unmarshaledDataSource.TargetType, targetMetadata.TargetType)
			assert.EqualExportedValues(t, targetMetadata.SourceCodeMetadata, targetMetadata.SourceCodeMetadata)
			assert.Equal(t, ocsffindinginfo.DataSource_URI_SCHEMA_FILE, targetMetadata.Uri.UriSchema)
			assert.True(t, strings.HasPrefix(unmarshaledDataSource.Uri.Path, targetMetadata.Uri.Path), unmarshaledDataSource.Uri.Path, targetMetadata.Uri.Path)
			assert.Contains(t, expectedSeverityValues, f.SeverityId, f.SeverityId)
		}
	})

	t.Run("ios: full report", func(t *testing.T) {
		jsonPath := filepath.Join("testdata", "dvia-v2-swift-report.json")
		tr, err := New(MobSFTransformerWithClock(clock), MobSFRawOutFilePath(jsonPath))
		require.NoError(t, err)

		targetMetadata := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "some-release.ipa",
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: repositoryURL,
				Reference:     commitRef,
			},
		}
		ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

		findings, err := tr.Transform(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		for _, f := range findings {
			assert.NotEmpty(t, f.FindingInfo.Title)
			assert.NotEmpty(t, f.FindingInfo.Desc)
			assert.NotNil(t, f.Severity)
			assert.NotEmpty(t, *f.Severity)
			require.NotEmpty(t, f.FindingInfo.DataSources)
			require.NotEmpty(t, f.FindingInfo.DataSources[0])

			unmarshaledDataSource := &ocsffindinginfo.DataSource{}
			require.NoError(t, protojson.Unmarshal([]byte(f.FindingInfo.DataSources[0]), unmarshaledDataSource))
			assert.Equal(t, unmarshaledDataSource.TargetType, targetMetadata.TargetType)
			assert.EqualExportedValues(t, targetMetadata.SourceCodeMetadata, targetMetadata.SourceCodeMetadata)
			assert.Equal(t, ocsffindinginfo.DataSource_URI_SCHEMA_FILE, targetMetadata.Uri.UriSchema)
			assert.True(t, strings.HasPrefix(unmarshaledDataSource.Uri.Path, targetMetadata.Uri.Path), unmarshaledDataSource.Uri.Path, targetMetadata.Uri.Path)
			assert.Contains(t, expectedSeverityValues, f.SeverityId, f.SeverityId)
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
