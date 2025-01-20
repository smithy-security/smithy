package v1

import (
	_ "embed"

	"github.com/go-errors/errors"
	"github.com/xeipuuv/gojsonschema"
)

type (
	// ComponentType represents all the types of components that Smithy supports.
	// ENUM(unknown, target, scanner, enricher, filter, reporter)
	ComponentType string

	// Component is a binary or a script that can be used in the context of a
	// workflow to generate some useful result.
	Component struct {
		// Description describes what the component will do.
		Description string `json:"description" yaml:"description"`
		// Name is the component name.
		Name string `json:"name" yaml:"name"`
		// Parameters is the list of parameters to be supplied to the component.
		Parameters []Parameter `json:"parameters" yaml:"parameters"`
		// Steps is the list of steps to be supplied to the component.
		Steps []Step `json:"steps" yaml:"steps"`
		// Type represents the component type.
		Type ComponentType `json:"type" yaml:"type"`
	}

	// Step represents an executing step inside a Component.
	Step struct {
		// Args is the list of arguments supplied to a component.
		Args []string `json:"args" yaml:"args"`
		// EnvVars is the set of environment variables key:val supplied to a component.
		EnvVars map[string]string `json:"env_vars" yaml:"env_vars"`
		// Name is the step name.
		Name string `json:"name" yaml:"name"`
		// Executable is the path to the entrypoint to run the component.
		Executable string `json:"executable" yaml:"executable"`
		// Images is the docker image to be run for this component.
		Image string `json:"image" yaml:"image"`
		// Script will be deprecated after rewriting all components.
		Script string `json:"script" yaml:"script"`
	}
)

//go:embed component.schema.json
var componentJSONSchema string

// Validate validates a component spec.
func (c *Component) Validate() error {
	var (
		schema        = gojsonschema.NewStringLoader(componentJSONSchema)
		jsonComponent = gojsonschema.NewGoLoader(c)
	)

	res, err := gojsonschema.Validate(schema, jsonComponent)
	if err != nil {
		return errors.Errorf("failed json-schema component validation: %w", err)
	}

	if !res.Valid() {
		var finalErr error
		for _, err := range res.Errors() {
			finalErr = errors.Join(finalErr, errors.New(err.String()))
		}
		return finalErr
	}

	return nil
}
