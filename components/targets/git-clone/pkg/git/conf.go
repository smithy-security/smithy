package git

import (
	"path"
	"strings"

	"github.com/smithy-security/pkg/env"
)

type (
	// Conf wraps the component configuration.
	Conf struct {
		RepoURL            string
		Reference          string
		BaseRef            string
		ClonePath          string
		TargetMetadataPath string
		RawDiffPath        string

		ConfAuth ConfAuth
	}

	// ConfAuth contains authentication configuration.
	ConfAuth struct {
		Username    string
		AccessToken string
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf() (*Conf, error) {
	repoURL, err := env.GetOrDefault("GIT_CLONE_REPO_URL", "")
	if err != nil {
		return nil, err
	}

	reference, err := env.GetOrDefault(
		"GIT_CLONE_REFERENCE",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	baseRef, err := env.GetOrDefault(
		"GIT_CLONE_BASE_REFERENCE",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	clonePath, err := env.GetOrDefault(
		"GIT_CLONE_PATH",
		"./repo",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	targetMetadataPath, err := env.GetOrDefault(
		"GIT_CLONE_TARGET_METADATA_PATH",
		"./repo",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	if targetMetadataPath != "" && !strings.HasSuffix(targetMetadataPath, "target.json") {
		targetMetadataPath = path.Join(targetMetadataPath, "target.json")
	}

	rawDiffOutPath, err := env.GetOrDefault(
		"GIT_RAW_DIFF_PATH",
		"./repo",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	if rawDiffOutPath != "" && !strings.HasSuffix(rawDiffOutPath, "raw.diff") {
		rawDiffOutPath = path.Join(rawDiffOutPath, "raw.diff")
	}

	accessUsername, err := env.GetOrDefault(
		"GIT_CLONE_ACCESS_USERNAME",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	accessToken, err := env.GetOrDefault(
		"GIT_CLONE_ACCESS_TOKEN",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	return &Conf{
		RepoURL:            repoURL,
		Reference:          reference,
		BaseRef:            baseRef,
		ClonePath:          clonePath,
		TargetMetadataPath: targetMetadataPath,
		RawDiffPath:        rawDiffOutPath,
		ConfAuth: ConfAuth{
			Username:    accessUsername,
			AccessToken: accessToken,
		},
	}, nil
}
