package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type goSecScanner struct {
	repoPath       string
	dockerTestPool *dockertest.Pool
}

func NewGoSecScanner(repoPath string) (*goSecScanner, error) {
	if repoPath == "" {
		return nil, errors.New("must specify a repository path")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %w", err)
	}

	return &goSecScanner{
		repoPath:       repoPath,
		dockerTestPool: pool,
	}, nil
}

func (g *goSecScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	p, err := filepath.Abs(".")
	if err != nil {
		return nil, fmt.Errorf("could not get absolute path: %w", err)
	}

	component.LoggerFromContext(ctx).Info("current abs path", slog.String("path", p))

	r, err := g.dockerTestPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "docker.io/securego/gosec",
		Tag:        "2.15.0",
		WorkingDir: "/workspace",
		Cmd: []string{
			"-r",
			"-sort",
			"-nosec",
			"-fmt=json",
			"-out=gosec_out.json",
			//"-no-fail",
			fmt.Sprintf("./%s/...", g.repoPath),
		},
		Mounts: []string{
			fmt.Sprintf("%s:/workspace", p),
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	if err != nil {
		return nil, fmt.Errorf("could not start gosec container: %w", err)
	}

	if err := g.dockerTestPool.Purge(r); err != nil {
		component.LoggerFromContext(ctx).Error("could not purge gosec container", slog.String("err", err.Error()))
	}

	return nil, nil
}
