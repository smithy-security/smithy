package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

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

// New returns a new configuration initialised by introspecting the environment variables.
func New() (Config, error) {
	var (
		err, errs error
		cfg       Config
	)

	cfg.Target.ArchivePath, err = env.GetOrDefault(
		"ARCHIVE_PATH",
		"./archive",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARCHIVE_PATH: %w", err))
	}

	cfg.Target.SourceCodePath, err = env.GetOrDefault(
		"SOURCE_CODE_PATH",
		"./source-code",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SOURCE_CODE_PATH: %w", err))
	}

	cfg.Metadata.MetadataPath, err = env.GetOrDefault(
		"METADATA_PATH",
		"./metadata",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var METADATA_PATH: %w", err))
	}

	if cfg.Metadata.MetadataPath != "" && !strings.HasSuffix(cfg.Metadata.MetadataPath, "target.json") {
		cfg.Metadata.MetadataPath = path.Join(cfg.Metadata.MetadataPath, "target.json")
	}

	var artifactURL string
	artifactURL, err = env.GetOrDefault(
		"ARTIFACT_URL",
		"",
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_URL: %w", err))
	}

	artifactExtension, err := env.GetOrDefault(
		"ARTIFACT_EXTENSION",
		"",
		env.WithDefaultOnError(true),
	)
	switch {
	case err != nil:
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_EXTENSION: %w", err))
	case artifactExtension != "":
		artifactURL += fmt.Sprintf(".%s", strings.TrimSuffix(artifactExtension, "."))
	}

	cfg.Fetcher.ArtifactURL = artifactURL
	cfg.Metadata.ArtifactURL = artifactURL
	cfg.Target.ArtifactURL = artifactURL

	cfg.Metadata.Reference, err = env.GetOrDefault(
		"ARTIFACT_REFERENCE",
		"",
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_REFERENCE: %w", err))
	}

	cfg.Fetcher.Region, err = env.GetOrDefault(
		"ARTIFACT_REGISTRY_REGION",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_REGISTRY_REGION: %w", err))
	}

	cfg.Fetcher.AuthID, err = env.GetOrDefault(
		"ARTIFACT_REGISTRY_AUTH_ID",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_REGISTRY_AUTH_ID: %w", err))
	}

	cfg.Fetcher.AuthSecret, err = env.GetOrDefault(
		"ARTIFACT_REGISTRY_AUTH_SECRET",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var ARTIFACT_REGISTRY_AUTH_SECRET: %w", err))
	}

	return cfg, errs
}
