package config

import (
	"github.com/smithy-security/pkg/env"
)

// Config is the struct containing all the configuration reuired by the components
type Config struct {
	GitDiffPath string
	Root        string
}

// New returns a configured Config struct based on the environment variables
func New() (Config, error) {
	rootDir, err := env.GetOrDefault(
		"WORKSPACE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return Config{}, err
	}

	gitDiff, err := env.GetOrDefault(
		"GIT_RAW_DIFF_PATH",
		".",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return Config{}, err
	}

	return Config{
		GitDiffPath: gitDiff,
		Root:        rootDir,
	}, nil
}
