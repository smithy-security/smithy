package git

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"strings"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
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
		// ShallowSubmodules limits cloning submodules to the 1 level of depth.
		// Makes cloning faster for submodules as we don't fetch their full git history.
		ShallowSubmodules: true,
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

	logger.Debug("checking out HEAD...")
	rh, err := repo.Head()
	if err != nil {
		return nil, errors.Errorf("error getting HEAD: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, errors.Errorf("error getting worktree: %w", err)
	}
	logger.Debug("successfully checked out HEAD!")

	logger.Debug("checking out references...")
	var isCheckoutErr bool
	for _, branch := range []plumbing.ReferenceName{
		plumbing.ReferenceName(path.Join("refs", "heads", mgr.conf.Reference)),
		plumbing.ReferenceName(path.Join("refs", "remotes", "origin", mgr.conf.Reference)),
	} {
		logger.Debug("checking out reference", slog.String("branch", branch.String()))
		checkoutErr := wt.Checkout(&git.CheckoutOptions{
			Branch: branch,
			Force:  true,
		})
		if checkoutErr != nil {
			logger.Warn("couldn't checkout branch, attempting next if available", slog.String("branch", branch.String()))
			isCheckoutErr = true
		} else {
			isCheckoutErr = false
		}
	}
	if isCheckoutErr {
		logger.Error("checking out reference failed")
		return nil, errors.Errorf("couldn't checkout branches for reference: %s", mgr.conf.Reference)
	}
	logger.Debug("successfully checked out references!")

	return &Repository{
		Repo:    repo,
		BaseRef: rh.Name().String(),
	}, nil
}

// GetDiff returns the raw git diff between the target reference and the base reference.
func (r *Repository) GetDiff() (string, error) {
	currRef, err := r.Repo.Head()
	switch {
	case err != nil:
		return "", errors.Errorf("could not get HEAD: %w", err)
	case currRef.Name().String() == r.BaseRef:
		return "", nil
	}

	currRefCommit, err := r.Repo.CommitObject(currRef.Hash())
	if err != nil {
		return "", errors.Errorf("error getting head commit: %w", err)
	}

	baseRefObj, err := r.Repo.Reference(plumbing.ReferenceName(r.BaseRef), true)
	if err != nil {
		return "", errors.Errorf("error getting base reference '%s': %w", r.BaseRef, err)
	}

	baseCommit, err := r.Repo.CommitObject(baseRefObj.Hash())
	if err != nil {
		return "", errors.Errorf("error getting base commit: %w", err)
	}

	patch, err := baseCommit.Patch(currRefCommit)
	if err != nil {
		return "", errors.Errorf("error generating patch: %w", err)
	}

	patchStr := patch.String()
	if patchStr == "" {
		return "", nil
	}

	files, _, err := gitdiff.Parse(strings.NewReader(patchStr))
	if err != nil {
		return "", errors.Errorf("error parsing patch with gitdiff: %w", err)
	}

	var sb strings.Builder
	for _, f := range files {
		sb.WriteString(fmt.Sprintf("diff --git a/%s b/%s\n", f.OldName, f.NewName))
		if f.IsBinary {
			sb.WriteString("Binary files differ\n\n")
			continue
		}

		for _, fragment := range f.TextFragments {
			sb.WriteString(
				fmt.Sprintf("@@ -%d,%d +%d,%d @@\n",
					fragment.OldPosition,
					fragment.OldLines,
					fragment.NewPosition,
					fragment.NewLines,
				),
			)

			for _, line := range fragment.Lines {
				sb.WriteString(line.Line)
				if !strings.HasSuffix(line.Line, "\n") {
					sb.WriteString("\n")
				}
			}
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
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
