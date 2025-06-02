package workflow

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/distribution/reference"
	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/utils"
	v1 "github.com/smithy-security/smithy/pkg/types/v1"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/smithy-security/smithy/smithyctl/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/images/docker"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

type (
	workflowAdapter struct {
		// Description described what the workflow is configured for.
		Description string `yaml:"description"`
		// Name is the name of the workflow.
		Name       string         `yaml:"name"`
		Components []ComponentRef `yaml:"components"`
	}

	// ComponentRef decouples from the v1 type to handle concrete, local or remote components.
	ComponentRef struct {
		Component Component `yaml:"component"`
	}

	// Component decouples from the v1 type to handle concrete, local or remote components.
	Component struct {
		pkgComponent             *v1.Component
		localComponentReference  *url.URL
		remoteComponentReference reference.Reference
	}

	// ComponentFetcher can be implemented to fetch packages.
	ComponentFetcher interface {
		FetchPackage(ctx context.Context, ref reference.Reference) (*registry.FetchPackageResponse, error)
	}

	// ComponentParser defines how to parse a component.yaml.
	ComponentParser interface {
		Parse(path string) (*v1.Component, error)
	}

	ComponentImageResolver interface {
		Remote() (images.Resolver, error)
		Local(context.Context, string) (images.Resolver, error)
	}

	imageResolver struct {
		remote func() (images.Resolver, error)
		local  func(context.Context, string) (images.Resolver, error)
	}

	specParser struct {
		componentFetcher ComponentFetcher
		componentParser  ComponentParser
		imageResolver    ComponentImageResolver
	}
)

// HasRemoteReference returns whether the component has a remote reference or not.
func (c *Component) HasRemoteReference() bool {
	return c.remoteComponentReference != nil
}

// HasLocalReference returns whether the component has a local reference or not.
func (c *Component) HasLocalReference() bool {
	return c.localComponentReference != nil
}

// IsInitialised returns whether the component has been initialised (not nil) or not.
func (c *Component) IsInitialised() bool {
	return c.pkgComponent != nil
}

func NewDockerImageResolver(
	buildComponentImages bool,
	dockerClient *dockerclient.Client,
	credsStore credentials.Store,
	opts ...dockerimages.BuilderOptionFn,
) (ComponentImageResolver, error) {
	if utils.IsNil(dockerClient) {
		return nil, errors.Errorf("nil docker client provided")
	}

	remoteComponentImageResolver, err := dockerimages.NewResolver(dockerClient, credsStore, false)
	if err != nil {
		return nil, errors.Errorf("could not initialise docker image resolver: %w", err)
	}

	dockerImageResolver := &imageResolver{
		remote: func() (images.Resolver, error) {
			return remoteComponentImageResolver, nil
		},
	}

	if buildComponentImages {
		dockerImageResolver.local = func(
			ctx context.Context,
			componentPath string,
		) (images.Resolver, error) {
			return dockerimages.NewResolverBuilder(
				ctx, dockerClient, componentPath, credsStore, false, opts...,
			)
		}
	} else {
		dockerImageResolver.local = func(_ context.Context, _ string) (images.Resolver, error) {
			return remoteComponentImageResolver, nil
		}
	}

	return dockerImageResolver, nil
}

func (i *imageResolver) Remote() (images.Resolver, error) {
	return i.remote()
}

func (i *imageResolver) Local(ctx context.Context, componentPath string) (images.Resolver, error) {
	return i.local(ctx, componentPath)
}

// NewSpecParser returns a new workflow spec parser.
func NewSpecParser(
	fetcher ComponentFetcher,
	componentParser ComponentParser,
	imageResolver ComponentImageResolver,
) (*specParser, error) {
	switch {
	case fetcher == nil:
		return nil, errors.New("componentFetcher is nil")
	case componentParser == nil:
		return nil, errors.New("component parser is nil")
	}

	return &specParser{
		componentFetcher: fetcher,
		componentParser:  componentParser,
		imageResolver:    imageResolver,
	}, nil
}

// UnmarshalYAML overrides default yaml unmarshalling to cover for remotes being specified in paths or remotely.
func (c *Component) UnmarshalYAML(unmarshal func(any) error) error {
	var stringValue string
	if err := unmarshal(&stringValue); err == nil {
		if strings.HasPrefix(stringValue, "file") {
			c.localComponentReference, err = url.Parse(stringValue)
			if err != nil {
				return errors.Errorf("component reference is not a valid local reference %q: %w", stringValue, err)
			}
			return nil
		}

		c.remoteComponentReference, err = reference.Parse(stringValue)
		if err != nil {
			return errors.Errorf("component reference is not a valid remote reference %q: %w", stringValue, err)
		}
		return nil
	}

	if err := unmarshal(&c.pkgComponent); err != nil {
		return errors.Errorf("invalid component reference %q: %v", stringValue, err)
	}

	return nil
}

type ParserConfig struct {
	SpecPath       string
	OverridesPath  string
	ResolutionOpts []images.ResolutionOptionFn
}

// Parse parses the workflow step into a correct format.
// If the component reference is remote, it fetches it and parses it.
// It also takes care of optional overrides and templating their values into the base component.
// Finally, it validates the workflow and returns it, ready to be executed.
func (sp *specParser) Parse(ctx context.Context, config ParserConfig) (*v1.Workflow, error) {
	rawWf, err := parseRawWorkflowSpec(config.SpecPath)
	if err != nil {
		return nil, err
	}

	overrides, err := parseOverrides(config.OverridesPath)
	if err != nil {
		return nil, err
	}

	var (
		wf = &v1.Workflow{
			Description: rawWf.Description,
			Name:        rawWf.Name,
			Stages:      make([]v1.Stage, 0),
		}
		components   = make([]*v1.Component, 0)
		componentMap = make(map[string]*v1.Component)
	)

	for _, c := range rawWf.Components {
		var (
			parsedComponent *v1.Component
			err             error
		)

		resolver, err := sp.imageResolver.Remote()
		if err != nil {
			return nil, errors.Errorf("could not bootstrap remote image resolver: %w", err)
		}

		switch {
		case c.Component.HasRemoteReference():
			parsedComponent, err = sp.parseRemoteComponent(ctx, c.Component.remoteComponentReference)
		case c.Component.HasLocalReference():
			parsedComponent, err = sp.parseLocalComponent(c.Component.localComponentReference)
			cleanedUp := &url.URL{
				Host: c.Component.localComponentReference.Host,
				Path: c.Component.localComponentReference.Path,
			}

			if err == nil {
				resolver, err = sp.imageResolver.Local(ctx, cleanedUp.String()[2:])
			}
		case c.Component.IsInitialised():
			parsedComponent = c.Component.pkgComponent
		default:
			err = errors.New("invalid component reference")
		}

		if err != nil {
			return nil, errors.Errorf("failed to parse a component: %w", err)
		}

		for index, step := range parsedComponent.Steps {
			renderedImageRef, err := resolver.Resolve(ctx, step.Image)
			if err != nil {
				return nil, errors.Errorf("%s: could not resolve image: %w", step.Image, err)
			}

			step.Image = renderedImageRef
			parsedComponent.Steps[index] = step
		}

		componentMap[parsedComponent.Name] = parsedComponent
		components = append(components, parsedComponent)
	}

	// Applying overrides.
	for i, component := range components {
		ovrParams, ok := overrides[component.Name]
		if !ok {
			continue
		}

		for j, componentParam := range component.Parameters {
			ovrParam, ok := ovrParams[componentParam.Name]
			if ok {
				components[i].Parameters[j] = ovrParam
			}
		}
	}

	// Rendering parameters using go templates.
	if err := renderComponents(components); err != nil {
		return nil, err
	}

	// Sorting components by stages.
	for _, ct := range v1.ComponentTypeValues() {
		if refs := filterComponents(components, ct); len(refs) > 0 {
			wf.Stages = append(wf.Stages, v1.Stage{ComponentRefs: refs})
		}
	}

	if err := wf.Validate(); err != nil {
		return nil, errors.Errorf("failed to validate workflow spec: %w", err)
	}

	return wf, nil
}

func (wa workflowAdapter) validate() error {
	for _, c := range wa.Components {
		switch {
		case c.Component.IsInitialised() && c.Component.pkgComponent == nil:
			return errors.Errorf("invalid component %q, empty details", c.Component.pkgComponent.Name)
		case c.Component.HasRemoteReference() && c.Component.remoteComponentReference == nil:
			return errors.Errorf("invalid component remote reference %q", c.Component.pkgComponent.Name)
		case c.Component.HasLocalReference() && c.Component.localComponentReference == nil:
			return errors.New("invalid component, it can be a remote reference or an actual component, not both")
		}
	}
	return nil
}

func (sp *specParser) parseRemoteComponent(ctx context.Context, ref reference.Reference) (*v1.Component, error) {
	resp, err := sp.componentFetcher.FetchPackage(ctx, ref)
	if err != nil {
		return nil, errors.Errorf("failed to fetch remote component: %w", err)
	}
	return &resp.Component, nil
}

func (sp *specParser) parseLocalComponent(reference *url.URL) (*v1.Component, error) {
	ap, err := filepath.Abs(path.Join(reference.Hostname(), reference.Path))
	if err != nil {
		return nil, errors.Errorf("failed to resolve absolute component path: %w", err)
	}

	c, err := sp.componentParser.Parse(ap)
	if err != nil {
		return nil, errors.Errorf("failed to parse local component: %v", err)
	}
	return c, nil
}

func parseRawWorkflowSpec(path string) (*workflowAdapter, error) {
	const (
		defaultSmithyWorkflowFileNameYaml = "workflow.yaml"
		defaultSmithyWorkflowFileNameYml  = "workflow.yml"
	)

	if !strings.HasSuffix(path, defaultSmithyWorkflowFileNameYaml) && !strings.HasSuffix(path, defaultSmithyWorkflowFileNameYml) {
		return nil, errors.Errorf(
			"invalid file path %s, has to be a workflow defintion YAML file named %s or %s",
			path, defaultSmithyWorkflowFileNameYaml, defaultSmithyWorkflowFileNameYml,
		)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("%s does not exist", path)
		}
		return nil, errors.Errorf("failed to read workflow config file: %w", err)
	}

	var workflow workflowAdapter
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&workflow); err != nil {
		return nil, errors.Errorf("failed to decode file '%s': %w", path, err)
	}

	return &workflow, workflow.validate()
}

// parseOverrides reads the overrides from the passed path and returns them organised
// by component name and parameter name.
func parseOverrides(path string) (map[string]map[string]v1.Parameter, error) {
	var overrides = make(map[string]map[string]v1.Parameter)
	// If the overrides haven't been specified, return early.
	if path == "" {
		return overrides, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("%s does not exist", path)
		}
		return nil, errors.Errorf("failed to read overrides file: %w", err)
	}

	var tmpOverrides map[string][]v1.Parameter
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&tmpOverrides); err != nil {
		return nil, errors.Errorf("failed to decode file overrides '%s': %w", path, err)
	}

	for componentName, params := range tmpOverrides {
		overrides[componentName] = make(map[string]v1.Parameter)
		for _, param := range params {
			if err := param.Validate(); err != nil {
				return nil, errors.Errorf("failed to validate override parameter for component '%s': %w", componentName, err)
			}
			overrides[componentName][param.Name] = param
		}
	}

	return overrides, nil
}

// filterComponents returns the components that match the passed component type.
func filterComponents(components []*v1.Component, componentType v1.ComponentType) []v1.ComponentRef {
	var filteredComponents []v1.ComponentRef
	for _, c := range components {
		if c.Type == componentType {
			filteredComponents = append(
				filteredComponents,
				v1.ComponentRef{
					Component: *c,
				},
			)
		}
	}
	return filteredComponents
}

// renderComponents templates parameters in component.yaml files.
// The parameters are always specified with a '.parameters' prefix.
func renderComponents(components []*v1.Component) error {
	for idx, component := range components {
		b, err := yaml.Marshal(component)
		if err != nil {
			return errors.Errorf("failed to YAML marshal component '%s': %w", component.Name, err)
		}

		var tmpl = template.New("componentAsStr").Funcs(
			// leave these two functions in place so that the execution engine
			// can use them as needed
			template.FuncMap{
				"scratchWorkspace": func() string {
					return "{{ scratchWorkspace }}"
				},
				"sourceCodeWorkspace": func() string {
					return "{{ sourceCodeWorkspace }}"
				},
				"targetMetadataWorkspace": func() string {
					return "{{ targetMetadataWorkspace }}"
				},
			},
		)

		tmpl, err = tmpl.Parse(string(b))
		if err != nil {
			return errors.Errorf("failed to parse component '%s' as template: %w", component.Name, err)
		}

		var tmplCtx = map[string]map[string]any{
			"parameters": make(map[string]any),
		}

		for _, param := range component.Parameters {
			tmplCtx["parameters"][param.Name] = param.Value
		}

		var bb bytes.Buffer
		if err := tmpl.Execute(&bb, tmplCtx); err != nil {
			return errors.Errorf("failed to render component '%s': %w", component.Name, err)
		}

		var templatedComponent v1.Component
		if err := yaml.Unmarshal(bb.Bytes(), &templatedComponent); err != nil {
			return errors.Errorf("failed to unmarshal templated component '%s': %w", component.Name, err)
		}

		components[idx] = &templatedComponent
	}

	return nil
}
