package config

import (
	"fmt"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
)

// Config contains the application's configuration.
type Config struct {
	RawOutFilePath string
	TargetType     string
}

// New returns a new configuration initialised by introspecting the environment variables.
func New() (Config, error) {
	var (
		err, errs error
		cfg       Config
	)

	cfg.RawOutFilePath, err = env.GetOrDefault("GOSEC_RAW_OUT_FILE_PATH", "gosec.json", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var GOSEC_RAW_OUT_FILE_PATH: %w", err))
	}

	cfg.TargetType, err = env.GetOrDefault("SMITHY_INSTANCE_NAME", "repository", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_INSTANCE_NAME: %w", err))
	}

	return cfg, errs
}
