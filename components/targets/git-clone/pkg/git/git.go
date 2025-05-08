package git

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/smithy-security/smithy/sdk/component"
)

const (
	errInvalidConfigurationStr         = "invalid option field '%s': %s"
	errInvalidConfigurationReasonEmpty = "cannot be empty"
)

type (
	// Repository wraps a git repository to not leak deps.
	Repository struct {
		repo *git.Repository
	}

	Manager struct {
		clonePath    string
		metadataPath string
		cloneOptions *git.CloneOptions
	}
)

// NewManager returns a new default clone Manager.
func NewManager(conf *Conf) (*Manager, error) {
	switch {
	case conf.RepoURL == "":
		return nil, fmt.Errorf(errInvalidConfigurationStr, "repo_url", errInvalidConfigurationReasonEmpty)
	case conf.Reference == "":
		return nil, fmt.Errorf(errInvalidConfigurationStr, "reference", errInvalidConfigurationReasonEmpty)
	}

	u, err := url.Parse(conf.RepoURL)
	if err != nil {
		return nil, fmt.Errorf(errInvalidConfigurationStr+": %w", "repo_url", "couldn't parse", err)
	}

	if conf.ClonePath == "" {
		conf.ClonePath, err = extractRepoName(u.Path)
		if err != nil {
			return nil, err
		}
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
			return nil, fmt.Errorf(errInvalidConfigurationStr, "auth_access_token", errInvalidConfigurationReasonEmpty)
		}
		if conf.ConfAuth.Username == "" {
			return nil, fmt.Errorf(errInvalidConfigurationStr, "auth_username", errInvalidConfigurationReasonEmpty)
		}
		opts.Auth = &http.BasicAuth{
			Username: conf.ConfAuth.Username,
			Password: conf.ConfAuth.AccessToken,
		}
	}

	return &Manager{
		clonePath:    conf.ClonePath,
		metadataPath: conf.TargetMetadataPath,
		cloneOptions: opts,
	}, nil
}

// Clone clones the configured repository.
func (mgr *Manager) Clone(ctx context.Context) (*Repository, error) {
	logger := component.
		LoggerFromContext(ctx).
		With(
			slog.String("clone_path", mgr.clonePath),
		)

	logger.Debug("cloning repository...")

	repo, err := git.PlainCloneContext(ctx, mgr.clonePath, false, mgr.cloneOptions)
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil, errors.Errorf("error cloning repository at '%s': %w", mgr.clonePath, err)
	}

	logger.Debug("successfully cloned repository")
	return &Repository{
		repo: repo,
	}, nil
}

func extractRepoName(path string) (string, error) {
	e, err := transport.NewEndpoint(path)
	if err != nil {
		return "", err
	}

	parts := strings.Split(e.Path, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf(errInvalidConfigurationStr, "repo_url", "must have at least 2 parts")
	}

	repo := parts[len(parts)-1]
	if strings.HasSuffix(repo, ".git") {
		return repo[:len(repo)-4], nil
	}

	return repo, nil
}
