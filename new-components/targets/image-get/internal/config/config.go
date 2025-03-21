package config

import (
	"github.com/smithy-security/pkg/env"
)

type Conf struct {
	ImageRef  string
	Username  string
	Token     string
	TargetDir string
}

// New returns a new configuration build from environment lookup.
func New(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	imageRef, err := env.GetOrDefault("IMAGE_REF", "", envOpts...)
	if err != nil {
		return nil, err
	}

	username, err := env.GetOrDefault("USERNAME", "", append(envOpts, env.WithDefaultOnError(true))...)
	if err != nil {
		return nil, err
	}

	token, err := env.GetOrDefault("TOKEN", "", append(envOpts, env.WithDefaultOnError(true))...)
	if err != nil {
		return nil, err
	}

	targetDir, err := env.GetOrDefault(
		"TARGET_DIR",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, err
	}
	return &Conf{
		ImageRef:  imageRef,
		Username:  username,
		Token:     token,
		TargetDir: targetDir,
	}, nil
}
