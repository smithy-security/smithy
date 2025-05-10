package config

import (
	"fmt"
	"net/url"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/components/reporters/discord/internal/discord"
)

// Config contains the application's configuration.
type Config struct {
	SmithyInstanceID   string
	SmithyInstanceName string
	SmithyDashURL      *url.URL
	Discord            discord.Config
}

// New returns a new configuration initialised by introspecting the environment variables.
func New() (Config, error) {
	var (
		err, errs error
		cfg       Config
	)

	cfg.SmithyInstanceID, err = env.GetOrDefault("SMITHY_INSTANCE_ID", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_INSTANCE_ID: %w", err))
	}

	cfg.SmithyInstanceName, err = env.GetOrDefault("SMITHY_INSTANCE_NAME", "smithy", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_INSTANCE_NAME: %w", err))
	}

	dashURL, err := env.GetOrDefault("SMITHY_PUBLIC_URL", "https://plexor.saas.smithy.security", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_PUBLIC_URL: %w", err))
	} else {
		cfg.SmithyDashURL, err = url.Parse(dashURL)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to pars env var SMITHY_PUBLIC_URL: %w", err))
		}
	}

	cfg.Discord.ChannelID, err = env.GetOrDefault("DISCORD_CHANNEL_ID", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var DISCORD_CHANNEL_ID: %w", err))
	}

	cfg.Discord.AuthToken, err = env.GetOrDefault("DISCORD_AUTH_TOKEN", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var DISCORD_AUTH_TOKEN: %w", err))
	}

	return cfg, errs
}
