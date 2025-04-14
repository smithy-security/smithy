package git

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/smithy-security/pkg/env"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
)

const (
	errInvalidConfigurationStr         = "invalid option field '%s': %s"
	errInvalidConfigurationReasonEmpty = "cannot be empty"
)

type (
	// Conf wraps the component configuration.
	Conf struct {
		RepoURL            string
		Reference          string
		ClonePath          string
		TargetMetadataPath string

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
		metadataPath string
		cloneOptions *git.CloneOptions
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	repoURL, err := env.GetOrDefault("GIT_CLONE_REPO_URL", "", envOpts...)
	if err != nil {
		return nil, err
	}

	reference, err := env.GetOrDefault("GIT_CLONE_REFERENCE", "", envOpts...)
	if err != nil {
		return nil, err
	}

	clonePath, err := env.GetOrDefault("GIT_CLONE_PATH", "", envOpts...)
	if err != nil {
		return nil, err
	}

	targetMetadataPath, err := env.GetOrDefault(
		"GIT_CLONE_TARGET_METADATA_PATH",
		"",
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, err
	}

	if targetMetadataPath != "" && !strings.HasSuffix(targetMetadataPath, "target.json") {
		targetMetadataPath = path.Join(targetMetadataPath, "target.json")
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
		RepoURL:            repoURL,
		Reference:          reference,
		ClonePath:          clonePath,
		TargetMetadataPath: targetMetadataPath,
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

	return &manager{
		clonePath:    conf.ClonePath,
		metadataPath: conf.TargetMetadataPath,
		cloneOptions: opts,
	}, nil
}

// Clone clones the configured repository.
func (mgr *manager) Clone(ctx context.Context) (*Repository, error) {
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

	if mgr.metadataPath == "" {
		return &Repository{
			repo: repo,
		}, nil
	}

	logger.Info("generating target metadata...")

	fd, err := os.OpenFile(mgr.metadataPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open file to report clone metadata: %w", err)
	}

	parsedURL, err := url.Parse(mgr.cloneOptions.URL)
	if err != nil {
		return nil, errors.Errorf("could not parse clone URL of the repository: %w", err)
	}

	if parsedURL.User != nil {
		parsedURL.User = nil
	}

	// remove the .git suffix to ensure everything is normalised
	parsedURL.Path = strings.TrimRight(parsedURL.Path, ".git")

	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: parsedURL.String(),
			Reference:     mgr.cloneOptions.ReferenceName.String(),
		},
	}

	marshaledDataSource, err := protojson.Marshal(dataSource)
	if err != nil {
		return nil, errors.Errorf("could not marshal data source into JSON: %w", err)
	}

	_, err = fd.Write(marshaledDataSource)
	if err != nil {
		return nil, errors.Errorf("could not write marshaled data source to file: %w", err)
	}

	logger.Debug(
		"wrote the following content for target metadata",
		slog.String("content", string(marshaledDataSource)),
		slog.String("file", mgr.metadataPath),
	)

	return &Repository{
		repo: repo,
	}, fd.Close()
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
