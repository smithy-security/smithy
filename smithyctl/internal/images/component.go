package images

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/go-errors/errors"
	"github.com/google/go-containerregistry/pkg/name"

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
	componentRepositoryRegex = regexp.MustCompile(fmt.Sprintf("([a-z-_]+/)?(%s)/[a-z-_]+", componentPluralisedTypeChoice))
	// ErrNotAComponentRepo is returns when an image repository doesn't match
	// the expected format
	ErrNotAComponentRepo = errors.Errorf("image repository doesn't match the expected component path: <component root directory>/%s/component.yaml", componentPluralisedTypeChoice)
)

// resolutionOptions is a struct that defines common properties of all the
// images of components managed by the system
type resolutionOptions struct {
	registry   string
	namespace  string
	defaultTag string
	extraTags  []string
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

// WithDefaultTag changes the tag that will be set by defaylt to an image if it
// doesn't have tag already
func WithDefaultTag(t string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		if t == "" {
			return errors.New("default tag should not be an empty string")
		}
		o.defaultTag = t
		return nil
	}
}

// WithDefaultTag changes the tag that will be set by default to all the
// component images
func WithExtraTags(tags ...string) ResolutionOptionFn {
	return func(o *resolutionOptions) error {
		o.extraTags = tags
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

func makeOptions(opts ...ResolutionOptionFn) (resolutionOptions, error) {
	defaultOpts := resolutionOptions{
		registry:   DefaultRegistry,
		namespace:  DefaultNamespace,
		defaultTag: DefaultTag,
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
	repository         name.Tag
	componentType      v1.ComponentType
	componentNamespace string
	componentName      string
	directory          string
	extraTags          []string
}

// ParseComponentRepository parses the component image repository and verifies
// that it references a smithy component
func ParseComponentRepository(componentPath, imageRef string, options ...ResolutionOptionFn) (*ComponentRepository, *name.Tag, error) {
	fmt.Fprintf(os.Stderr, "parsing component repository: %s %s\n", componentPath, imageRef)

	opts, err := makeOptions(options...)
	if err != nil {
		return nil, nil, errors.Errorf("there was an error while parsing the resolution options: %w", err)
	}

	componentDirectory := path.Dir(componentPath)
	parsedRef, err := name.NewTag(
		imageRef,
		name.WithDefaultTag(opts.defaultTag),
		name.WithDefaultRegistry(opts.registry),
	)
	if err != nil {
		return nil, nil, errors.Errorf("could not parse image reference: %w", err)
	}

	// a Smithy component image reference should be of the form
	// some-folder/scanners/gosec and in order for us to be able to recognise
	// it, it should be included in a component residing in the directory
	// some-folder/scanners/gosec. if this is not the case, it's not recognised
	// as a Smithy component image reference and we will just return the parsed
	// image reference.
	if !strings.HasPrefix(parsedRef.RepositoryStr(), componentDirectory) {
		return nil, &parsedRef, errors.Errorf("%s: %w", parsedRef.Name(), ErrNotAComponentRepo)
	}

	// a Smithy component image and its directory should be of the form
	// some-folder/[one of our component types]/component-name
	if !componentRepositoryRegex.MatchString(parsedRef.RepositoryStr()) {
		return nil, &parsedRef, errors.Errorf("%s: %w", parsedRef.Name(), ErrNotAComponentRepo)
	}

	// get the component type from the path
	componentDirectoryParts := strings.Split(componentDirectory, "/")
	rawComponentType := componentDirectoryParts[len(componentDirectoryParts)-2]
	rawComponentType, exists := pluralToSingularComponentType[rawComponentType]
	if !exists {
		return nil, &parsedRef, errors.Errorf(
			"%s: can't recognise component type: %w", rawComponentType, ErrNotAComponentRepo,
		)
	}

	componentType, err := v1.ParseComponentType(rawComponentType)
	if err != nil {
		return nil, &parsedRef, errors.Errorf(
			"%s: there was an error parsing the component type of the image: %w: %w", rawComponentType, err, ErrNotAComponentRepo,
		)
	}

	return &ComponentRepository{
		repository:         parsedRef,
		componentType:      componentType,
		componentNamespace: opts.namespace,
		componentName: strings.TrimLeft(
			strings.Replace(
				parsedRef.RepositoryStr(),
				path.Dir(componentDirectory), "", -1),
			"/",
		),
		directory: parsedRef.RepositoryStr(),
		extraTags: opts.extraTags,
	}, &parsedRef, nil
}

// Repo returns the repository of the component image
func (cr *ComponentRepository) Repo() string {
	return path.Join(cr.componentNamespace, cr.repository.RepositoryStr())
}

// Tag returns the default tag of the component image
func (cr *ComponentRepository) Tag() string {
	return cr.repository.TagStr()
}

// Directory is the complete path to the root of the component
// It is relative to the root of the repository
func (cr *ComponentRepository) Directory() string {
	return cr.directory
}

// Type returns the component type of the component
func (cr *ComponentRepository) Type() v1.ComponentType {
	return cr.componentType
}

// Name returns the name of the component
func (cr *ComponentRepository) Name() string {
	return cr.componentName
}

// Registry returns the name of the component
func (cr *ComponentRepository) Registry() string {
	return cr.repository.RegistryStr()
}

// URL returns the complete registry, namespace, repository and the default tag
// of the image
func (cr *ComponentRepository) URL() string {
	return path.Join(cr.repository.RegistryStr(), cr.Repo()) + ":" + cr.Tag()
}

// URLs returns all the component image URLs, not just the one tagged with the
// default tag
func (cr *ComponentRepository) URLs() []string {
	urls := []string{cr.URL()}
	for _, tag := range cr.extraTags {
		urls = append(urls, path.Join(cr.repository.RegistryStr(), cr.Repo())+":"+tag)
	}

	return urls
}
