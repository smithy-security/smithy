package images

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-errors/errors"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/smithy-security/pkg/utils"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

var (
	pluralToSingularComponentType = map[string]string{}
	componentPluralisedTypeChoice = strings.Join(
		slices.Collect(
			func(yield func(string) bool) {
				for _, ct := range v1.ComponentTypeNames() {
					if ct != v1.ComponentTypeUnknown.String() {
						pluralToSingularComponentType[ct+"s"] = ct
						if !yield(ct + "s") {
							return
						}
					}
				}
			},
		),
		"|",
	)
)

// resolutionOptions is a struct that defines common properties of all the
// images of components managed by the system
type resolutionOptions struct {
	registry          string
	namespace         string
	tags              []string
	replacements      map[string]string
	imageRefProcessor ImageRepoProcessor
}

// ResolutionOptionFn is used to define common attributes of all the images
// of components
type ResolutionOptionFn func(*resolutionOptions) error

// WithRegistry changes the registry that will be used for all the images
func WithRegistry(r string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		if r == "" {
			return errors.New("registry should not be an empty string")
		}
		o.registry = r
		return nil
	}
}

// WithTags changes the tag that will be set by default to all the component
// images
func WithTags(tags ...string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		o.tags = tags
		return nil
	}
}

// WithNamespace changes the namespace used for all the component images
func WithNamespace(n string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		o.namespace = n
		return nil
	}
}

// WithImageReplacements sets a map that will be used to replace images before
// resolving them
func WithImageReplacements(imageReplacements map[string]string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		o.replacements = imageReplacements
		return nil
	}
}

// WithImageProcessor adds a processor that will modify the image in an
// arbitrary way
func WithImageProcessor(processor ImageRepoProcessor) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		if utils.IsNil(processor) {
			return errors.New("processor provided is nil")
		}
		o.imageRefProcessor = processor
		return nil
	}
}

func makeOptions(opts ...ResolutionOptionFn) (resolutionOptions, error) {
	defaultOpts := resolutionOptions{
		registry:          DefaultRegistry,
		namespace:         DefaultNamespace,
		imageRefProcessor: NoOpImageRepoProcessor{},
		tags:              []string{"latest"},
	}

	for _, opt := range opts {
		if err := opt(&defaultOpts); err != nil {
			return resolutionOptions{}, err
		}
	}

	return defaultOpts, nil
}

// ComponentRepository represents a container image repository of a Smithy
// component. It also captures metadata such as the directory of the component
// and allows a caller to get the complete registry, repository and tag URL of
// the image
type ComponentRepository struct {
	registry           string
	repository         string
	componentType      v1.ComponentType
	componentNamespace string
	componentName      string
	directory          string
	urls               []string
	tags               []string
}

func replaceImageURL(replacements map[string]string, ref *name.Tag) (*name.Tag, error) {
	// there might be a replacement for the complete image URL:tag or there
	// might be a replacement for just the repository
	replacement, exists := replacements[ref.Name()]
	if !exists {
		replacement, exists = replacements[ref.RepositoryStr()]
	}

	if exists {
		parsedReplacement, err := name.NewTag(replacement)
		if err != nil {
			return nil, errors.Errorf("%s => %s: could not parse image replacement image: %w", ref.Name(), replacement, err)
		}

		return &parsedReplacement, nil
	}

	return nil, nil
}

// ParseComponentRepository parses the component image repository and verifies
// that it references a smithy component
func ParseComponentRepository(componentPath, imageRef string, options ...ResolutionOptionFn) (*ComponentRepository, *name.Tag, error) {
	fmt.Fprintf(os.Stderr, "parsing image reference: %s %s\n", componentPath, imageRef)

	componentDirectory := path.Dir(componentPath)
	parsedRef, err := name.NewTag(imageRef)
	if err != nil {
		return nil, nil, errors.Errorf("could not parse image reference: %w", err)
	}

	opts, err := makeOptions(options...)
	if err != nil {
		return nil, nil, errors.Errorf("there was an error while parsing the image resolution options: %w", err)
	}

	replacedRef, replacementErr := replaceImageURL(opts.replacements, &parsedRef)
	if replacedRef != nil {
		return nil, replacedRef, replacementErr
	} else if !filepath.IsLocal(imageRef) {
		return nil, &parsedRef, nil
	}

	fileInfo, err := os.Stat(imageRef)
	if err != nil || !fileInfo.IsDir() {
		return nil, &parsedRef, nil
	}

	// get the component type from the path
	componentRepository := opts.imageRefProcessor.Process(
		path.Join(
			opts.namespace,
			parsedRef.RepositoryStr(),
		),
	)

	cr := &ComponentRepository{
		componentNamespace: opts.namespace,
		componentName: strings.TrimLeft(
			strings.Replace(
				parsedRef.RepositoryStr(),
				path.Dir(componentDirectory), "", -1),
			"/",
		),
		directory:  parsedRef.RepositoryStr(),
		registry:   opts.registry,
		repository: componentRepository,
		tags:       opts.tags,
	}

	componentAndRegistry := path.Join(opts.registry, componentRepository)
	cr.urls = []string{}
	for _, tag := range opts.tags {
		cr.urls = append(cr.urls, componentAndRegistry+":"+tag)
	}

	return cr, &parsedRef, nil
}

// Repo returns the repository of the component image
func (cr *ComponentRepository) Repo() string {
	return cr.repository
}

// Tags returns the default tag of the component image
func (cr *ComponentRepository) Tags() []string {
	return cr.tags
}

// Directory is the complete path to the root of the component
// It is relative to the root of the repository
func (cr *ComponentRepository) Directory() string {
	return cr.directory
}

// Registry returns the name of the component
func (cr *ComponentRepository) Registry() string {
	return cr.registry
}

// URLs returns all the component image URLs, not just the one tagged with the
// default tag
func (cr *ComponentRepository) URLs() []string {
	return cr.urls
}
