package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	dockerimage "github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

type dockerPuller interface {
	ImagePull(ctx context.Context, refStr string, options dockerimage.PullOptions) (io.ReadCloser, error)
}

// Resolver uses the docker client to pull an image
type Resolver struct {
	client dockerPuller
}

// NewResolver returns a bootstrapped instance of the resolver based on a
// Docker client
func NewResolver(client dockerPuller) (*Resolver, error) {
	if utils.IsNil(client) {
		var err error
		client, err = dockerclient.NewClientWithOpts(dockerclient.FromEnv)
		if err != nil {
			return nil, errors.Errorf("failed to create docker client: %w", err)
		}
	}

	return &Resolver{client: client}, nil
}

// Resolve fetches an image from a container registry
func (s *Resolver) Resolve(ctx context.Context, imageRef string, _ ...images.ResolutionOptionFn) (string, error) {
	// if the image does not refer to a smithy component or is not tagged as
	// the latest version of the image we just try to pull it
	readCloser, err := s.client.ImagePull(ctx, imageRef, dockerimage.PullOptions{})
	if err != nil {
		return "", errors.Errorf("%s: could not pull image; %w", imageRef, err)
	}

	_, err = fmt.Fprintf(os.Stderr, "pulling image %s", imageRef)
	if err != nil {
		return "", errors.Errorf("could not output to stderr: %w", err)
	}

	_, err = io.Copy(os.Stderr, readCloser)
	if err != nil {
		return "", errors.Errorf("could not redirect docker daemon output to stderr: %w", err)
	}

	return imageRef, nil
}
