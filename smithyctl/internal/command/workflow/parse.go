package workflow

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/distribution/reference"
	"github.com/go-errors/errors"
	"gopkg.in/yaml.v3"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

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

	specParser struct {
		componentFetcher ComponentFetcher
		componentParser  ComponentParser
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

// NewSpecParser returns a new workflow spec parser.
func NewSpecParser(fetcher ComponentFetcher, componentParser ComponentParser) (*specParser, error) {
	switch {
	case fetcher == nil:
		return nil, errors.New("componentFetcher is nil")
	case componentParser == nil:
		return nil, errors.New("component parser is nil")
	}
	return &specParser{
		componentFetcher: fetcher,
		componentParser:  componentParser,
	}, nil
}

// UnmarshalYAML overrides default yaml unmarshalling to cover for remotes being specified in paths or remotely.
func (c *Component) UnmarshalYAML(unmarshal func(interface{}) error) error {
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

// Parse parses the workflow step into a correct format.
// If the component reference is remote, it fetches it and parses it.
// It also takes care of optional overrides and templating their values into the base component.
// Finally, it validates the workflow and returns it, ready to be executed.
func (sp *specParser) Parse(
	ctx context.Context,
	specPath string,
	overridesPath string,
) (*v1.Workflow, error) {
	rawWf, err := parseRawWorkflowSpec(specPath)
	if err != nil {
		return nil, err
	}

	overrides, err := parseOverrides(overridesPath)
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
		errs         error
	)

	for _, c := range rawWf.Components {
		var (
			parsedComponent *v1.Component
			err             error
		)

		switch {
		case c.Component.HasRemoteReference():
			parsedComponent, err = sp.parseRemoteComponent(ctx, c.Component.remoteComponentReference)
		case c.Component.HasLocalReference():
			parsedComponent, err = sp.parseLocalComponent(c.Component.localComponentReference)
		case c.Component.IsInitialised():
			parsedComponent = c.Component.pkgComponent
		default:
			err = errors.New("invalid component reference")
		}

		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		componentMap[parsedComponent.Name] = parsedComponent
		components = append(components, parsedComponent)
	}

	if errs != nil {
		return nil, errors.Errorf("failed to parse components: %w", errs)
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
	for _, ct := range []v1.ComponentType{
		v1.ComponentTypeTarget,
		v1.ComponentTypeScanner,
		v1.ComponentTypeEnricher,
		v1.ComponentTypeFilter,
		v1.ComponentTypeReporter,
	} {
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
			return fmt.Errorf("invalid component %q, empty details", c.Component.pkgComponent.Name)
		case c.Component.HasRemoteReference() && c.Component.remoteComponentReference == nil:
			return fmt.Errorf("invalid component remote reference %q", c.Component.pkgComponent.Name)
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
			"invalid file path %s, has to either point to a component file",
			path,
		)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("%s does not exist", path)
		}
		return nil, fmt.Errorf("failed to read workflow config file: %w", err)
	}

	var workflow workflowAdapter
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&workflow); err != nil {
		return nil, fmt.Errorf("failed to decode file '%s': %w", path, err)
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
		return nil, fmt.Errorf("failed to read overrides file: %w", err)
	}

	var tmpOverrides map[string][]v1.Parameter
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&tmpOverrides); err != nil {
		return nil, fmt.Errorf("failed to decode file overrides '%s': %w", path, err)
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

		var tmpl = template.New("componentAsStr")

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
