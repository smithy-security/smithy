package config

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
)

func TestConfigParsing(t *testing.T) {
	t.Run("config with paths to files", func(t *testing.T) {
		archiveFolder := t.TempDir()
		archiveFile := path.Join(archiveFolder, "archive")
		sourceCodeFolder := t.TempDir()
		metadataFolder := t.TempDir()
		metadataFile := path.Join(metadataFolder, "target.json")

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.tar.gz"

		require.NoError(t, os.Setenv(EnvVarArchivePath, archiveFile))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, ""))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		cfg, err := New()
		require.NoError(t, err)
		assert.Equal(t, artifactURL, cfg.Target.ArtifactURL)
		assert.Equal(t, archiveFile, cfg.Target.ArchivePath)
		assert.Equal(t, sourceCodeFolder, cfg.Target.SourceCodePath)
		assert.Equal(t, artifact.FileTypeTarGz, cfg.Metadata.FileType)
		assert.Equal(t, artifactURL, cfg.Metadata.ArtifactURL)
		assert.Equal(t, metadataFile, cfg.Metadata.MetadataPath)
	})

	t.Run("archive path is inferred", func(t *testing.T) {
		archiveFolder := t.TempDir()
		archiveFile := path.Join(archiveFolder, "v1.0.12.tar.gz")
		sourceCodeFolder := t.TempDir()
		metadataFolder := t.TempDir()
		metadataFile := path.Join(metadataFolder, "target.json")

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.tar.gz"

		require.NoError(t, os.Setenv(EnvVarArchivePath, archiveFolder))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, ""))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		cfg, err := New()
		require.NoError(t, err)
		assert.Equal(t, artifactURL, cfg.Target.ArtifactURL)
		assert.Equal(t, archiveFile, cfg.Target.ArchivePath)
		assert.Equal(t, sourceCodeFolder, cfg.Target.SourceCodePath)
		assert.Equal(t, artifact.FileTypeTarGz, cfg.Metadata.FileType)
		assert.Equal(t, artifactURL, cfg.Metadata.ArtifactURL)
		assert.Equal(t, metadataFile, cfg.Metadata.MetadataPath)
	})

	t.Run("unarchived file is downloaded in source code path", func(t *testing.T) {
		archiveFolder := t.TempDir()
		sourceCodeFolder := t.TempDir()
		sourceCodeFile := path.Join(sourceCodeFolder, "v1.0.12.apk")
		metadataFolder := t.TempDir()
		metadataFile := path.Join(metadataFolder, "target.json")

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.apk"

		require.NoError(t, os.Setenv(EnvVarArchivePath, archiveFolder))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, ""))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		cfg, err := New()
		require.NoError(t, err)
		assert.Equal(t, artifactURL, cfg.Target.ArtifactURL)
		assert.Equal(t, sourceCodeFile, cfg.Target.ArchivePath)
		assert.Equal(t, sourceCodeFile, cfg.Target.SourceCodePath)
		assert.Equal(t, artifact.FileTypeUnarchived, cfg.Metadata.FileType)
		assert.Equal(t, artifactURL, cfg.Metadata.ArtifactURL)
		assert.Equal(t, metadataFile, cfg.Metadata.MetadataPath)
	})

	t.Run("archive type is fetched from environment", func(t *testing.T) {
		archiveFolder := t.TempDir()
		archiveFile := path.Join(archiveFolder, "v1.0.12.apk")
		sourceCodeFolder := t.TempDir()
		metadataFolder := t.TempDir()
		metadataFile := path.Join(metadataFolder, "target.json")

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.apk"

		require.NoError(t, os.Setenv(EnvVarArchivePath, archiveFolder))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, "zip"))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		cfg, err := New()
		require.NoError(t, err)
		assert.Equal(t, artifactURL, cfg.Target.ArtifactURL)
		assert.Equal(t, archiveFile, cfg.Target.ArchivePath)
		assert.Equal(t, sourceCodeFolder, cfg.Target.SourceCodePath)
		assert.Equal(t, artifact.FileTypeZip, cfg.Metadata.FileType)
		assert.Equal(t, artifactURL, cfg.Metadata.ArtifactURL)
		assert.Equal(t, metadataFile, cfg.Metadata.MetadataPath)
	})

	t.Run("archive type from file extension takes precedence", func(t *testing.T) {
		archiveFolder := t.TempDir()
		archiveFile := path.Join(archiveFolder, "archive")
		sourceCodeFolder := t.TempDir()
		metadataFolder := t.TempDir()
		metadataFile := path.Join(metadataFolder, "target.json")

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.tar.gz"

		require.NoError(t, os.Setenv(EnvVarArchivePath, archiveFile))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, "zip"))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		cfg, err := New()
		require.NoError(t, err)
		assert.Equal(t, artifactURL, cfg.Target.ArtifactURL)
		assert.Equal(t, archiveFile, cfg.Target.ArchivePath)
		assert.Equal(t, sourceCodeFolder, cfg.Target.SourceCodePath)
		assert.Equal(t, artifact.FileTypeTarGz, cfg.Metadata.FileType)
		assert.Equal(t, artifactURL, cfg.Metadata.ArtifactURL)
		assert.Equal(t, metadataFile, cfg.Metadata.MetadataPath)
	})

	t.Run("archive file is wrong", func(t *testing.T) {
		archiveFolder := t.TempDir()
		archiveFile := path.Join(archiveFolder, "archive")
		wrongArchiveFile := path.Join(archiveFile, "archive")
		sourceCodeFolder := t.TempDir()
		metadataFolder := t.TempDir()

		artifactURL := "https://github.com/B3nac/InjuredAndroid/archive/refs/tags/v1.0.12.tar.gz"

		require.NoError(t, os.Setenv(EnvVarArchivePath, wrongArchiveFile))
		require.NoError(t, os.Setenv(EnvVarSourceCodePath, sourceCodeFolder))
		require.NoError(t, os.Setenv(EnvVarMetadataPath, metadataFolder))
		require.NoError(t, os.Setenv(EnvVarArchiveType, "zip"))
		require.NoError(t, os.Setenv(EnvVarArtifactURL, artifactURL))

		_, err := New()
		require.Error(t, err)
	})
}
