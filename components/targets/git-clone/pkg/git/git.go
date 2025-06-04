package git

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path"
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
		Repo    *git.Repository
		BaseRef string
	}

	Manager struct {
		conf         *Conf
		cloneOptions *git.CloneOptions
	}
)

// NewManager returns a new default clone Manager.
func NewManager(conf *Conf) (*Manager, error) {
	switch {
	case conf.RepoURL == "":
		return nil, fmt.Errorf(errInvalidConfigurationStr, "repo_url", errInvalidConfigurationReasonEmpty)
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
		// ShallowSubmodules limits cloning submodules to the 1 level of depth.
		// Makes cloning faster for submodules as we don't fetch their full git history.
		ShallowSubmodules: true,
		// URL specifies the repository url.
		URL: u.String(),
		// ReferenceName is the reference name.
		ReferenceName: plumbing.ReferenceName(conf.Reference),
	}

	// This is off by default to facilitate local setup.
	if conf.ConfAuth.AccessToken == "" && conf.ConfAuth.Username != "" {
		return nil, fmt.Errorf(errInvalidConfigurationStr, "auth_access_token", errInvalidConfigurationReasonEmpty)
	}

	if conf.ConfAuth.Username == "" && conf.ConfAuth.AccessToken != "" {
		return nil, fmt.Errorf(errInvalidConfigurationStr, "auth_username", errInvalidConfigurationReasonEmpty)
	}

	if conf.ConfAuth.AccessToken != "" {
		opts.Auth = &http.BasicAuth{
			Username: conf.ConfAuth.Username,
			Password: conf.ConfAuth.AccessToken,
		}
	}

	return &Manager{
		conf:         conf,
		cloneOptions: opts,
	}, nil
}

// Clone clones the configured repository from its default references and then checks out in the target reference
// if it differs from the base.
func (mgr *Manager) Clone(ctx context.Context) (*Repository, error) {
	var (
		clonePath = mgr.conf.ClonePath
		logger    = component.
				LoggerFromContext(ctx).
				With(
				slog.String("clone_path", clonePath),
			)
	)

	logger.Debug("cloning repository...")
	repo, err := git.PlainCloneContext(ctx, clonePath, false, mgr.cloneOptions)
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil, errors.Errorf("error cloning repository at '%s': %w", clonePath, err)
	}
	logger.Debug("successfully cloned repository")

	return &Repository{
		BaseRef: mgr.conf.BaseRef,
		Repo:    repo,
	}, nil
}

// GetDiff returns the raw git diff between the target reference and the base reference.
// We try to resolve the base branch based on the passed configuration on relying on default branches main/master.
func (r *Repository) GetDiff(ctx context.Context) (string, error) {
	logger := component.LoggerFromContext(ctx)

	currRef, err := r.Repo.Head()
	if err != nil {
		return "", errors.Errorf("could not get HEAD: %w", err)
	}

	currRefCommit, err := r.Repo.CommitObject(currRef.Hash())
	if err != nil {
		return "", errors.Errorf("error getting head commit: %w", err)
	}

	var baseRefCommit *plumbing.Reference = nil
	if r.BaseRef != "" {
		if r.BaseRef == currRef.Name().String() {
			logger.Debug("the passed base reference and target base reference is the same, skipping diff step")
			return "", nil
		}

		logger.Debug("getting base ref from passed base reference...")
		baseRefCommit, err = r.getRef([]string{
			r.BaseRef,
			path.Join("refs/remotes/origin", r.BaseRef),
			path.Join("refs/heads", r.BaseRef),
		})
		if err != nil {
			return "", errors.Errorf("error getting reference commit for passed base reference: %w", err)
		}
	} else {
		logger.Debug("getting base ref from default references (main/master)...")
		baseRefCommit, err = r.getRef([]string{
			"refs/remotes/origin/main",
			"refs/remotes/origin/master",
			"refs/heads/main",
			"refs/heads/master",
		})
		if err != nil {
			return "", errors.Errorf("error getting reference commit for passed base reference: %w", err)
		}
	}

	if baseRefCommit == nil {
		return "", errors.Errorf("could not find base reference")
	}

	baseCommit, err := r.Repo.CommitObject(baseRefCommit.Hash())
	if err != nil {
		return "", errors.Errorf("error getting base commit: %w", err)
	}

	patch, err := baseCommit.PatchContext(ctx, currRefCommit)
	if err != nil {
		return "", errors.Errorf("error generating patch: %w", err)
	}

	return patch.String(), nil
}

func (r *Repository) getRef(potentialRefs []string) (*plumbing.Reference, error) {
	var (
		ref *plumbing.Reference = nil
		err error
	)
	for _, currRef := range potentialRefs {
		ref, err = r.Repo.Reference(plumbing.ReferenceName(currRef), true)
		if err != nil {
			continue
		}
		break
	}

	if ref == nil {
		return nil, errors.Errorf("could not find base reference")
	}

	return ref, nil
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
