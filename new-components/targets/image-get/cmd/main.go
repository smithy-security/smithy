package main

import (
	"context"
	"log"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/config"
	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/docker"
	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/target"
	"github.com/smithy-security/smithy/sdk/component"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return errors.Errorf("failed to bootstrap docker client: %w", err)
	}

	conf, err := config.New(nil)
	dockerResolver, err := docker.NewResolver(dockerClient, conf)
	imageDownloaderTarget, _ := target.New(conf, target.WithResolver(dockerResolver))
	opts := append(make([]component.RunnerOption, 0), component.RunnerWithComponentName("oci-image-download"))
	if err := component.RunTarget(
		ctx,
		imageDownloaderTarget,
		opts...,
	); err != nil {
		return errors.Errorf("could not run target: %w", err)
	}

	return nil
}
