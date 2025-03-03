package images

import "context"

// Resolver is an interface implemented by objects that take an image reference
// and will make sure that the image becomes available for the local daemon to
// use and execute it. If the image can't be fetched, an error should be
// returned, otherwise the renderend image registry, repository and tag are
// returned.
type Resolver interface {
	Resolve(ctx context.Context, imageRef string, options ...ResolutionOptionFn) (string, error)
}

// Builder is an interface implemented by objects that take an image reference
// and resolve it to one of the paths in the local file system where the
// component code base is expected to reside and build the image in a
// standardised manner. If the component requires some special way of being
// built, that should be defined in another way and this builder is not
// expected to provide some extra functionality for the time being
type Builder interface {
	Build(ctx context.Context, cr *ComponentRepository) (string, error)
}
