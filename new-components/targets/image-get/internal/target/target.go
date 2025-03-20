package target

import (
	"context"

	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"

	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/config"
	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/docker"
)

type (
	ociImageDownloaderTarget struct {
		conf     *config.Conf
		resolver *docker.Resolver
		clock    clockwork.Clock
	}

	ociImageDownloaderTargetOption func(*ociImageDownloaderTarget) error
)

// WithClock allows customising the default clock. Mainly used for testing.
func WithClock(clock clockwork.Clock) ociImageDownloaderTargetOption {
	return func(gct *ociImageDownloaderTarget) error {
		if clock == nil {
			return errors.New("invalid nil clock")
		}
		gct.clock = clock
		return nil
	}
}

// WithCloner allows customising the default cloner. Mainly used for testing.
func WithResolver(resolver *docker.Resolver) ociImageDownloaderTargetOption {
	return func(gct *ociImageDownloaderTarget) error {
		if resolver == nil {
			return errors.New("invalid nil cloner")
		}
		gct.resolver = resolver
		return nil
	}
}

// New returns a new docker downloader target.
func New(conf *config.Conf, opts ...ociImageDownloaderTargetOption) (*ociImageDownloaderTarget, error) {
	gt := ociImageDownloaderTarget{
		conf:  conf,
		clock: clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&gt); err != nil {
			return nil, errors.Errorf("could not apply option: %w", err)
		}
	}

	if gt.resolver == nil {
		var err error
		dockerClient, err := dockerclient.NewClientWithOpts(
			dockerclient.FromEnv,
			dockerclient.WithAPIVersionNegotiation(),
		)
		if err != nil {
			return nil, errors.Errorf("failed to bootstrap docker client: %w", err)
		}

		gt.resolver, err = docker.NewResolver(dockerClient, conf)

		if err != nil {
			return nil, errors.Errorf("could not create cloner: %w", err)
		}
	}

	return &gt, nil
}

// Prepare saves an image from a target registry to a desired path.
func (g *ociImageDownloaderTarget) Prepare(ctx context.Context) error {
	_, err := g.resolver.Resolve(ctx)
	return err
}
