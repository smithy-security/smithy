package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-git/go-git/v5"

	"github.com/smithy-security/smithy/sdk/component"
)

type gitCloneTarget struct {
	repositoryURL string
	clonePath     string
}

func NewGitCloneTarget(repositoryURL string, clonePath string) (*gitCloneTarget, error) {
	switch {
	case repositoryURL == "":
		return nil, fmt.Errorf("repositoryURL is empty")
	case clonePath == "":
		return nil, fmt.Errorf("clonePath is empty")
	}
	return &gitCloneTarget{repositoryURL: repositoryURL, clonePath: clonePath}, nil
}

func (g *gitCloneTarget) Prepare(ctx context.Context) error {
	logger := component.
		LoggerFromContext(ctx).
		With(slog.String("repository_url", g.repositoryURL)).
		With(slog.String("clone_path", g.clonePath))

	logger.Debug("preparing to clone repo")

	if _, err := git.PlainClone(g.clonePath, false, &git.CloneOptions{
		URL:               g.repositoryURL,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	}); err != nil {
		return fmt.Errorf("could not clone repository: %w", err)
	}

	logger.Debug("successfully cloned repo")

	return nil
}
