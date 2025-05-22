package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear/client"
)

// Config contains the application's configuration.
type Config struct {
	SmithyInstanceID   string
	SmithyInstanceName string
	SmithyDashURL      *url.URL
	Linear             client.Config
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

	linearBaseURL, err := env.GetOrDefault("LINEAR_BASE_URL", "https://api.linear.app/graphql", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_BASE_URL: %w", err))
	}

	cfg.Linear.BaseURL, err = url.Parse(linearBaseURL)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to parse linear base URL '%s': %w", linearBaseURL, err))
	}

	cfg.Linear.TeamID, err = env.GetOrDefault("LINEAR_TEAM_ID", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_TEAM_ID: %w", err))
	}

	cfg.Linear.APIKey, err = env.GetOrDefault("LINEAR_API_KEY", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_API_KEY: %w", err))
	}

	cfg.Linear.RequestBatchSize, err = env.GetOrDefault("LINEAR_REQUEST_BATCH_SIZE", 10, env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_REQUEST_BATCH_SIZE: %w", err))
	}

	linearLabelNames, err := env.GetOrDefault("LINEAR_LABEL_NAMES", "", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_LABEL_NAMES: %w", err))
	}

	cfg.Linear.IssueLabelsNames = strings.Split(linearLabelNames, ",")
	return cfg, errs
}
