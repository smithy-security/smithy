package component

import (
	"bytes"
	"os"
	"path"
	"strings"

	"github.com/go-errors/errors"
	"gopkg.in/yaml.v3"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithy/smithyctl/utils"
)

type specParser struct{}

// NewSpecParser returns a new component spec parser.
func NewSpecParser() *specParser {
	return &specParser{}
}

// Parse reads, parses and validates components' configuration.
func (sp *specParser) Parse(componentPath string) (*v1.Component, error) {
	const (
		defaultSmithyComponentFileNameYaml = "component.yaml"
		defaultSmithyComponentFileNameYml  = "component.yml"
	)

	if !strings.HasSuffix(componentPath, defaultSmithyComponentFileNameYaml) && !strings.HasSuffix(componentPath, defaultSmithyComponentFileNameYml) {
		return nil, errors.Errorf(
			"invalid file path %s, has to point to a component file",
			componentPath,
		)
	}

	b, err := os.ReadFile(componentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("%s does not exist", componentPath)
		}
		return nil, errors.Errorf("failed to read config file: %w", err)
	}

	var component v1.Component
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&component); err != nil {
		return nil, errors.Errorf("failed decode file '%s': %w", componentPath, err)
	}

	if err := component.Validate(); err != nil {
		return nil, errors.Errorf("invalid component spec: %w", err)
	}

	componentDir := path.Dir(componentPath)
	componentName := path.Base(componentDir)
	if componentName != component.Name {
		return nil, errors.Errorf("component should have the same name as the path it's in: %s, %s", componentPath, component.Name)
	}

	componentType, err := utils.ComponentTypeFromPlural(path.Base(path.Dir(componentDir)))
	if err != nil {
		return nil, errors.Errorf(
			"components should be in a folder with the pluralised type of the component and the component name: %w",
			err,
		)
	}

	if component.Type != componentType {
		return nil, errors.Errorf(
			"component type in the manifest doesn't match the expected type based on the path: %s, %s",
			componentType, component.Type,
		)
	}

	return &component, nil
}
