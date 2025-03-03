package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	dockerimagetypes "github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

type Client interface {
	ImagePull(ctx context.Context, refStr string, options dockerimagetypes.PullOptions) (io.ReadCloser, error)
	dockerBuilder
}

// ResolverBuilder is a struct that resolves the path to a component and builds
// the component image in a standardised way. If the image is not one of the
// component images, it will be pulled
type ResolverBuilder struct {
	*Resolver
	*Builder
}

// NewResolverBuilder returns an instance of the ResolverBuilder which will
// pull images unless they are referring to smithy components with the latest
// tag
func NewResolverBuilder(
	ctx context.Context,
	client Client,
	componentPath string,
	opts ...BuilderOptionFn,
) (*ResolverBuilder, error) {
	var err error

	if utils.IsNil(client) {
		client, err = dockerclient.NewClientWithOpts(dockerclient.FromEnv)
		if err != nil {
			return nil, errors.Errorf("failed to create docker client: %w", err)
		}
	}

	builder, err := NewBuilder(ctx, client, componentPath, opts...)
	if err != nil {
		return nil, errors.Errorf("could not bootstrap builder: %w", err)
	}

	resolver, err := NewResolver(client)
	if err != nil {
		return nil, errors.Errorf("could not bootstrap resolver: %w", err)
	}

	return &ResolverBuilder{resolver, builder}, nil
}

// Resolve will attempt to pull an image unless it refers to a Smithy component
// and is not tagged with latest
func (r *ResolverBuilder) Resolve(
	ctx context.Context,
	imageRef string,
	options ...images.ResolutionOptionFn,
) (string, error) {
	cr, parsedRef, err := images.ParseComponentRepository(r.Builder.componentPath, imageRef, options...)
	if errors.Is(err, images.ErrNotAComponentRepo) {
		return r.Resolver.Resolve(ctx, parsedRef.String())
	} else if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "image %s is a reference to a component. building\n", imageRef)
	return r.Build(ctx, cr)
}
