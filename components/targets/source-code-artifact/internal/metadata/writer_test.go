package metadata_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/metadata"
)

func TestWriter_WriteMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	t.Run("write metadata for source code containing artifact", func(t *testing.T) {
		testDir := t.TempDir()

		config := metadata.Config{
			ArtifactURL:   "https://github.com/smithy-security/smithy/archive/6b327c4c75844f221acaf2da391f7f5a23286116.zip",
			RepositoryURL: "https://github.com/smithy-security",
			ArtifactID:    "",
			Reference:     "6b327c4c75844f221acaf2da391f7f5a23286116",
			MetadataPath:  filepath.Join(testDir, "metadata.json"),
		}

		writer := metadata.NewWriter(config)
		err := writer.WriteMetadata(ctx)
		require.NoError(t, err)

		_, err = os.Stat(config.MetadataPath)
		require.NoError(t, err, "metadata file should exist")

		fileContent, err := os.ReadFile(config.MetadataPath)
		require.NoError(t, err)
		require.NotEmpty(t, fileContent, "file should not be empty")

		var actualData ocsffindinginfo.DataSource
		require.NoError(t, protojson.Unmarshal(fileContent, &actualData))

		require.Equal(t, ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY, actualData.TargetType)
		require.NotNil(t, actualData.SourceCodeMetadata)
		require.Equal(t, "https://github.com/smithy-security", actualData.SourceCodeMetadata.RepositoryUrl)
		require.Equal(t, "6b327c4c75844f221acaf2da391f7f5a23286116", actualData.SourceCodeMetadata.Reference)
		require.Empty(t, actualData.Uri.Path)
	})

	t.Run("write metadata for artifact built from source code", func(t *testing.T) {
		testDir := t.TempDir()

		config := metadata.Config{
			ArtifactURL:   "https://github.com/B3nac/InjuredAndroid/releases/download/v1.0.12/InjuredAndroid-1.0.12-release.apk",
			RepositoryURL: "https://github.com/B3nac/InjuredAndroid",
			ArtifactID:    "apk-release-1.0.12",
			Reference:     "1.0.12",
			MetadataPath:  filepath.Join(testDir, "metadata.json"),
		}

		writer := metadata.NewWriter(config)
		err := writer.WriteMetadata(ctx)
		require.NoError(t, err)

		_, err = os.Stat(config.MetadataPath)
		require.NoError(t, err, "metadata file should exist")

		fileContent, err := os.ReadFile(config.MetadataPath)
		require.NoError(t, err)
		require.NotEmpty(t, fileContent, "file should not be empty")

		var actualData ocsffindinginfo.DataSource
		require.NoError(t, protojson.Unmarshal(fileContent, &actualData))

		require.Equal(t, ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY, actualData.TargetType)
		require.NotNil(t, actualData.SourceCodeMetadata)
		require.Equal(t, "https://github.com/B3nac/InjuredAndroid", actualData.SourceCodeMetadata.RepositoryUrl)
		require.Equal(t, "1.0.12", actualData.SourceCodeMetadata.Reference)
		require.Equal(t, "apk-release-1.0.12", actualData.Uri.Path)
	})
}
