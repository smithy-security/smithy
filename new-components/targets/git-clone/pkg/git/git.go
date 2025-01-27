package git

import (
	"context"
	"fmt"
	"net/url"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/smithy-security/pkg/env"
)

const (
	errInvalidConfigurationStr         = "invalid option field '%s': %s"
	errInvalidConfigurationReasonEmpty = "cannot be empty"
)

type (
	// Conf wraps the component configuration.
	Conf struct {
		ClonePath string
		RepoURL   string
		Reference string

		ConfAuth ConfAuth
	}

	// ConfAuth contains authentication configuration.
	ConfAuth struct {
		Username    string
		AuthEnabled bool
		AccessToken string
	}

	// Repository wraps a git repository to not leak deps.
	Repository struct {
		repo *git.Repository
	}

	manager struct {
		clonePath    string
		cloneOptions *git.CloneOptions
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	clonePath, err := env.GetOrDefault(
		"GIT_CLONE_PATH",
		".",
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, err
	}

	repoURL, err := env.GetOrDefault("GIT_CLONE_REPO_URL", "", envOpts...)
	if err != nil {
		return nil, err
	}

	reference, err := env.GetOrDefault("GIT_CLONE_REFERENCE", "", envOpts...)
	if err != nil {
		return nil, err
	}

	authEnabled, err := env.GetOrDefault(
		"GIT_CLONE_AUTH_ENABLED",
		false,
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, err
	}

	accessToken, err := env.GetOrDefault(
		"GIT_CLONE_ACCESS_TOKEN", "", append(envOpts, env.WithDefaultOnError(true))...)
	if err != nil {
		return nil, err
	}

	accessUsername, err := env.GetOrDefault(
		"GIT_CLONE_ACCESS_USERNAME",
		"smithy@smithy.security",
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, err
	}

	return &Conf{
		ClonePath: clonePath,
		RepoURL:   repoURL,
		Reference: reference,
		ConfAuth: ConfAuth{
			Username:    accessUsername,
			AuthEnabled: authEnabled,
			AccessToken: accessToken,
		},
	}, nil
}

// NewManager returns a new default clone manager.
func NewManager(conf *Conf) (*manager, error) {
	switch {
	case conf.RepoURL == "":
		return nil, errors.Errorf(errInvalidConfigurationStr, "repo_url", errInvalidConfigurationReasonEmpty)
	case conf.Reference == "":
		return nil, errors.Errorf(errInvalidConfigurationStr, "reference", errInvalidConfigurationReasonEmpty)
	case conf.ClonePath == "":
		return nil, errors.Errorf(errInvalidConfigurationStr, "clone_path", errInvalidConfigurationReasonEmpty)
	}

	u, err := url.Parse(conf.RepoURL)
	if err != nil {
		return nil, errors.Errorf(errInvalidConfigurationStr+": %w", "repo_url", "couldn't parse", err)
	}

	opts := &git.CloneOptions{
		// Depth 1 specifies that we want to check out the last commit only.
		// Makes cloning faster as we don't get the full git history.
		Depth: 1,
		// ReferenceName is the reference name.
		ReferenceName: plumbing.ReferenceName(conf.Reference),
		// ShallowSubmodules limits cloning submodules to the 1 level of depth.
		// Makes cloning faster for submodules as we don't fetch their full git history.
		ShallowSubmodules: true,
		// SingleBranch lets us fetch only the passed branch.
		// Makes cloning faster as we don't fetch all the branches.
		SingleBranch: true,
		// URL specifies the repository url.
		URL: u.String(),
	}

	// This is off by default to facilitate local setup.
	if conf.ConfAuth.AuthEnabled {
		if conf.ConfAuth.AccessToken == "" {
			return nil, errors.Errorf(errInvalidConfigurationStr, "auth_access_token", errInvalidConfigurationReasonEmpty)
		}
		if conf.ConfAuth.Username == "" {
			return nil, errors.Errorf(errInvalidConfigurationStr, "auth_username", errInvalidConfigurationReasonEmpty)
		}
		opts.Auth = &http.BasicAuth{
			Username: conf.ConfAuth.Username,
			Password: conf.ConfAuth.AccessToken,
		}
	}

	return &manager{
		clonePath:    conf.ClonePath,
		cloneOptions: opts,
	}, nil
}

// Clone clones the configured repository.
func (mgr *manager) Clone(ctx context.Context) (*Repository, error) {
	repo, err := git.PlainCloneContext(ctx, mgr.clonePath, false, mgr.cloneOptions)
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil, errors.Errorf("error cloning repository at '%s': %w", mgr.clonePath, err)
	}

	return &Repository{
		repo: repo,
	}, nil
}
