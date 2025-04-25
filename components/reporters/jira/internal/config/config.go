package config

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer/jira"
)

type Config struct {
	Jira jira.Config
}

func New() (Config, error) {
	var (
		err, errs error
		cfg       Config
	)

	cfg.Jira.SmithyInstanceID, err = env.GetOrDefault("SMITHY_INSTANCE_ID", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_INSTANCE_ID: %w", err))
	}

	cfg.Jira.SmithyInstanceName, err = env.GetOrDefault("SMITHY_INSTANCE_NAME", "smithy", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_INSTANCE_NAME: %w", err))
	}

	dashURL, err := env.GetOrDefault("SMITHY_PUBLIC_URL", "https://plexor.saas.smithy.security", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var SMITHY_PUBLIC_URL: %w", err))
	} else {
		cfg.Jira.SmithyDashURL, err = url.Parse(dashURL)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to pars env var SMITHY_PUBLIC_URL: %w", err))
		}
	}

	jiraBaseURL, err := env.GetOrDefault("JIRA_BASE_URL", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_BASE_URL: %w", err))
	} else {
		cfg.Jira.BaseURL, err = url.Parse(jiraBaseURL)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to pars env var JIRA_BASE_URL: %w", err))
		}
	}

	cfg.Jira.Project, err = env.GetOrDefault("JIRA_PROJECT", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_PROJECT: %w", err))
	}

	cfg.Jira.IssueType, err = env.GetOrDefault("JIRA_ISSUE_TYPE", "Task", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_ISSUE_TYPE: %w", err))
	}

	cfg.Jira.ClientMaxRetries, err = env.GetOrDefault("JIRA_CLIENT_MAX_RETRIES", uint(5), env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_CLIENT_MAX_RETRIES: %w", err))
	}

	cfg.Jira.AuthEnabled, err = env.GetOrDefault("JIRA_AUTH_ENABLED", false, env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_AUTH_ENABLED: %w", err))
	}

	cfg.Jira.AuthUsername, err = env.GetOrDefault("JIRA_AUTH_USERNAME", "smithy", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_AUTH_USERNAME: %w", err))
	}

	cfg.Jira.AuthPassword, err = env.GetOrDefault("JIRA_AUTH_PASSWORD", "passwd", env.WithDefaultOnError(true))
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var JIRA_AUTH_PASSWORD: %w", err))
	}

	return cfg, errs
}
