package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/go-errors/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

type dockerPuller interface {
	ImagePull(ctx context.Context, refStr string, options dockerimage.PullOptions) (io.ReadCloser, error)
}

// Resolver uses the docker client to pull an image
type Resolver struct {
	client dockerPuller
	report images.Report
	dryRun bool
}

// NewResolver returns a bootstrapped instance of the resolver based on a
// Docker client
func NewResolver(client dockerPuller, dryRun bool) (*Resolver, error) {
	if utils.IsNil(client) {
		return nil, ErrNoDockerClient
	}
	return &Resolver{
		client: client,
		dryRun: dryRun,
		report: images.Report{
			ExternalImages: sets.Set[string]{},
		},
	}, nil
}

// Resolve fetches an image from a container registry
func (r *Resolver) Resolve(ctx context.Context, imageRef string, _ ...images.ResolutionOptionFn) (string, error) {
	r.report.ExternalImages.Insert(imageRef)
	if r.dryRun {
		return imageRef, nil
	}

	// if the image does not refer to a smithy component or is not tagged as
	// the latest version of the image we just try to pull it
	readCloser, err := r.client.ImagePull(ctx, imageRef, dockerimage.PullOptions{})
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

// Report returns a report of all the images that the resolver pulled
func (r *Resolver) Report() images.Report {
	return images.Report{
		CustomImages:   r.report.CustomImages[:],
		ExternalImages: r.report.ExternalImages.Clone(),
	}
}
