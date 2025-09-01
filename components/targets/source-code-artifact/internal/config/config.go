package config

import (
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/metadata"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/target"
)

// Config contains the application's configuration.
type Config struct {
	Target   target.Config
	Fetcher  fetcher.Config
	Metadata metadata.Config
}

const (
	// EnvVarArchivePath is the environment variable for the archive path
	EnvVarArchivePath = "ARCHIVE_PATH"
	// EnvVarSourceCodePath is the environment variable for the source code
	// path
	EnvVarSourceCodePath = "SOURCE_CODE_PATH"
	// EnvVarMetadataPath is the environment variable for the metadata path
	EnvVarMetadataPath = "METADATA_PATH"
	// EnvVarArtifactURL is the environment variable for the archive url
	EnvVarArtifactURL = "ARTIFACT_URL"
	// EnvVarArchiveType is the environment variable for the archive type
	EnvVarArchiveType = "ARCHIVE_TYPE"
	// EnvVarArtifactReference is the environment variable for the artifact
	// reference
	EnvVarArtifactReference = "ARTIFACT_REFERENCE"
	// EnvVarArtifactRegistryRegion is the environment variable for the
	// registry region when the S3 client is used
	EnvVarArtifactRegistryRegion = "ARTIFACT_REGISTRY_REGION"
	// EnvVarArtifactRegistryAuthID is the environment variable for the client
	// secret ID in the case of the S3 client
	EnvVarArtifactRegistryAuthID = "ARTIFACT_REGISTRY_AUTH_ID"
	// EnvVarArtifactRegistryAuthSecret is the environment variable for the
	// secret of the S3 client
	EnvVarArtifactRegistryAuthSecret = "ARTIFACT_REGISTRY_AUTH_SECRET"
)

// New returns a new configuration initialised by introspecting the environment variables.
//
//revive:disable:cyclomatic High complexity score but easy to understand
func New() (Config, error) {
	var (
		err, errs error
		cfg       Config
	)

	cfg.Target.ArchivePath, err = env.GetOrDefault(
		EnvVarArchivePath,
		"./archive",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARCHIVE_PATH: %w", err))
	}

	cfg.Target.SourceCodePath, err = env.GetOrDefault(
		EnvVarSourceCodePath,
		"./source-code",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var SOURCE_CODE_PATH: %w", err))
	}

	cfg.Metadata.MetadataPath, err = env.GetOrDefault(
		EnvVarMetadataPath,
		"./metadata",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var METADATA_PATH: %w", err))
	}

	if cfg.Metadata.MetadataPath != "" && !strings.HasSuffix(cfg.Metadata.MetadataPath, "target.json") {
		cfg.Metadata.MetadataPath = path.Join(cfg.Metadata.MetadataPath, "target.json")
	}

	var artifactURL string
	artifactURL, err = env.GetOrDefault(
		EnvVarArtifactURL,
		"",
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARTIFACT_URL: %w", err))
	}

	archiveTypeStr, err := env.GetOrDefault(
		EnvVarArchiveType,
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARCHIVE_TYPE: %w", err))
	}

	archiveType, err := artifact.GetArchiveType(archiveTypeStr)
	if err != nil {
		errs = errors.Join(errs, err)
	}

	cfg.Fetcher.ArtifactURL = artifactURL
	cfg.Metadata.ArtifactURL = artifactURL
	cfg.Target.ArtifactURL = artifactURL

	cfg.Metadata.Reference, err = env.GetOrDefault(
		EnvVarArtifactReference,
		"",
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARTIFACT_REFERENCE: %w", err))
	}

	cfg.Fetcher.Region, err = env.GetOrDefault(
		EnvVarArtifactRegistryRegion,
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARTIFACT_REGISTRY_REGION: %w", err))
	}

	cfg.Fetcher.AuthID, err = env.GetOrDefault(
		EnvVarArtifactRegistryAuthID,
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARTIFACT_REGISTRY_AUTH_ID: %w", err))
	}

	cfg.Fetcher.AuthSecret, err = env.GetOrDefault(
		EnvVarArtifactRegistryAuthSecret,
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("failed to get env var ARTIFACT_REGISTRY_AUTH_SECRET: %w", err))
	}

	cfg.Metadata.FileType, err = artifact.GetFileType(cfg.Target.ArtifactURL)
	if err != nil {
		errs = errors.Join(errs, errors.Errorf("there was an error getting archive type: %w", err))
	}

	if errs != nil {
		return cfg, errs
	}

	if cfg.Metadata.FileType == artifact.FileTypeUnarchived {
		cfg.Metadata.FileType = archiveType
	}

	parsedURL, err := url.Parse(cfg.Target.ArtifactURL)
	if err != nil {
		return cfg, errors.Errorf("could not parse artifact URL: %w", err)
	}
	artifactNameComponents := strings.Split(parsedURL.Path, "/")
	artifactFileName := artifactNameComponents[len(artifactNameComponents)-1]

	if cfg.Metadata.FileType == artifact.FileTypeUnarchived {
		cfg.Target.SourceCodePath = path.Join(
			cfg.Target.SourceCodePath,
			artifactFileName,
		)

		// wire the archive path to be the same as  the source code path
		cfg.Target.ArchivePath = cfg.Target.SourceCodePath
	} else {
		archivePathStat, err := os.Stat(cfg.Target.ArchivePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return cfg, errors.Errorf("could not stat archive path: %w", err)
		} else if errors.Is(err, os.ErrNotExist) {
			// archive path is path to a file, make sure that its directory exists
			archiveDir := path.Dir(cfg.Target.ArchivePath)
			archivePathStat, err = os.Stat(archiveDir)
			if err != nil {
				return cfg, errors.Errorf(
					"%s: could not stat archive directory: %w", archiveDir, err,
				)
			} else if !archivePathStat.IsDir() {
				return cfg, errors.Errorf("%s is a file, not a directory", archiveDir)
			}
		} else if err == nil && archivePathStat.IsDir() {
			cfg.Target.ArchivePath = path.Join(
				cfg.Target.ArchivePath,
				artifactFileName,
			)
		}
	}

	return cfg, nil
}
