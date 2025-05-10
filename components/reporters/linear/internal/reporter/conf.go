package reporter

import (
	"fmt"
	"net/url"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
)

type Conf struct {
	LinearAPIKey  string
	LinearBaseURL *url.URL
	// SmithyInstanceID is the uuid representing the instance id in smithy. This is used for enriching the finding.
	SmithyInstanceID string
	// SmithyInstanceName is the instance name in smithy. This is used for enriching the finding.
	SmithyInstanceName string
	// SmithyDashURL is instance URL backing a smithy instance.
	SmithyDashURL *url.URL
}

func NewConf() (Conf, error) {
	var (
		cfg  Conf
		err  error
		errs error
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

	linearBaseURLStr, err := env.GetOrDefault(
		"LINEAR_BASE_URL",
		"https://api.linear.app/graphql",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get LINEAR_BASE_URL: %w", err))
	} else {
		cfg.LinearBaseURL, err = url.Parse(linearBaseURLStr)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to parse LINEAR_BASE_URL: %w", err))
		}
	}

	cfg.LinearAPIKey, err = env.GetOrDefault("LINEAR_API_KEY", "")
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to get env var LINEAR_API_KEY: %w", err))
	}

	return cfg, errs
}
