package images

import (
	"context"

	"k8s.io/apimachinery/pkg/util/sets"
)

// Resolver is an interface implemented by objects that take an image reference
// and will make sure that the image becomes available for the local daemon to
// use and execute it. If the image can't be fetched, an error should be
// returned, otherwise the renderend image registry, repository and tag are
// returned.
type Resolver interface {
	Resolve(ctx context.Context, imageRef string, options ...ResolutionOptionFn) (string, error)
	Report() Report
}

// Builder is an interface implemented by objects that take an image reference
// and resolve it to one of the paths in the local file system where the
// component code base is expected to reside and build the image in a
// standardised manner. If the component requires some special way of being
// built, that should be defined in another way and this builder is not
// expected to provide some extra functionality for the time being
type Builder interface {
	Build(ctx context.Context, cr *ComponentRepository) (string, error)
	Report() Report
}

// ImageRepoProcessor is an interface for an object that can modify the
// repository of a container in an arbitrary way. This is only going to be
// applied to component images
type ImageRepoProcessor interface {
	Process(repo string) string
}

// NoOpImageURLProcessor is a struct that is a no-op image repository processor
// meant to be used by default by resolvers and builders
type NoOpImageRepoProcessor struct{}

// Process is a no-op processor for the container image URL
func (n NoOpImageRepoProcessor) Process(repo string) string {
	return repo
}

// Report is a struct containing metadata about all the operations that a
// builder performed when processing the images of a component
type Report struct {
	CustomImages   []CustomImageReport `json:"custom_images" yaml:"custom_images"`
	ExternalImages sets.Set[string]    `json:"external_images" yaml:"external_images"`
}

// CustomImageReport captures all the data related to the building of a custom
// image build
type CustomImageReport struct {
	Tags          []string          `json:"tags" yaml:"tags"`
	Labels        map[string]string `json:"labels" yaml:"labels"`
	BuildArgs     map[string]string `json:"build_args" yaml:"build_args"`
	ContextPath   string            `json:"context_path" yaml:"context_path"`
	Dockerfile    string            `json:"dockerfile" yaml:"dockerfile"`
	ComponentPath string            `json:"component_path" yaml:"component_path"`
	Platform      string            `json:"platform" yaml:"platform"`
}
