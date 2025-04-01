package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	dockerimagetypes "github.com/docker/docker/api/types/image"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/utils"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/smithy-security/smithy/smithyctl/images"
)

type Client interface {
	ImagePull(ctx context.Context, refStr string, options dockerimagetypes.PullOptions) (io.ReadCloser, error)
	dockerBuilder
}

// ResolverBuilder is a struct that resolves the path to a component and builds
// the component image in a standardised way. If the image is not one of the
// component images, it will be pulled
type ResolverBuilder struct {
	resolver *Resolver
	builder  *Builder
	report   images.Report
	dryRun   bool
}

// NewResolverBuilder returns an instance of the ResolverBuilder which will
// pull images unless they are referring to smithy components with the latest
// tag
func NewResolverBuilder(
	ctx context.Context,
	client Client,
	componentPath string,
	dryRun bool,
	opts ...BuilderOptionFn,
) (*ResolverBuilder, error) {
	if utils.IsNil(client) {
		return nil, ErrNoDockerClient
	}

	builder, err := NewBuilder(ctx, client, componentPath, dryRun, opts...)
	if err != nil {
		return nil, errors.Errorf("could not bootstrap builder: %w", err)
	}

	resolver, err := NewResolver(client, dryRun)
	if err != nil {
		return nil, errors.Errorf("could not bootstrap resolver: %w", err)
	}

	return &ResolverBuilder{
		resolver: resolver,
		builder:  builder,
		report: images.Report{
			CustomImages:   []images.CustomImageReport{},
			ExternalImages: sets.New[string](),
		},
		dryRun: dryRun,
	}, nil
}

// Resolve will attempt to pull an image unless it refers to a Smithy component
// and is not tagged with latest
func (r *ResolverBuilder) Resolve(
	ctx context.Context,
	imageRef string,
	options ...images.ResolutionOptionFn,
) (string, error) {
	cr, parsedRef, err := images.ParseComponentRepository(r.builder.componentPath, imageRef, options...)
	if err != nil {
		return "", errors.Errorf("there was an error while processing image URL: %w", err)
	} else if cr == nil {
		return r.resolver.Resolve(ctx, parsedRef.String())
	}

	fmt.Fprintf(os.Stderr, "image %s is a reference to a component. building\n", imageRef)
	return r.builder.Build(ctx, cr)
}

// Report returns a report of all the images that have been resolved or built
func (r *ResolverBuilder) Report() images.Report {
	resolverReport := r.resolver.Report()
	customImages := r.builder.Report()
	return images.Report{
		CustomImages:   customImages.CustomImages[:],
		ExternalImages: resolverReport.ExternalImages,
	}
}
