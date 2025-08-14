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
	const testDir = "./testdata"
	require.NoError(t, os.MkdirAll(testDir, 0750))

	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(testDir))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config := metadata.Config{
		ArtifactURL:  "https://github.com/example/repo.git",
		Reference:    "main",
		MetadataPath: filepath.Join(testDir, "metadata.json"),
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
	require.Equal(t, "https://github.com/example/repo.git", actualData.SourceCodeMetadata.RepositoryUrl)
	require.Equal(t, "main", actualData.SourceCodeMetadata.Reference)
}
