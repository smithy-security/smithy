package v1

import (
	_ "embed"

	"github.com/go-errors/errors"
	"github.com/xeipuuv/gojsonschema"
)

type (
	// Workflow represents a combination of
	Workflow struct {
		// Description described what the workflow is configured for.
		Description string `json:"description" yaml:"description"`
		// Name is the name of the workflow.
		Name string `json:"name" yaml:"name"`
		// Stages contains the stages to be applied by the workflow.
		Stages []Stage `json:"stages" yaml:"stages"`
	}

	// Stage is a group of Components that can be executed in parallel during in
	// the context of a Workflow Instance.
	Stage struct {
		// ComponentRefs contains the list of component references attached to this stage.
		ComponentRefs []ComponentRef `json:"component_refs" yaml:"component_refs"`
	}

	// ComponentRef represents a reference to a component along with some overrides
	// that the user needs to declare.
	ComponentRef struct {
		// Component represents the linked component.
		Component Component `json:"component,omitempty" yaml:"component,omitempty"`
		// Overrides contains first later of parameter overrides for this component.
		Overrides []Parameter `json:"overrides" yaml:"overrides"`
	}
)

//go:embed workflow.schema.json
var workflowJSONSchema string

// Validate validates a workflow spec.
func (w *Workflow) Validate() error {
	var (
		schema       = gojsonschema.NewStringLoader(workflowJSONSchema)
		jsonWorkflow = gojsonschema.NewGoLoader(w)
	)

	res, err := gojsonschema.Validate(schema, jsonWorkflow)
	if err != nil {
		return errors.Errorf("failed json-schema workflow validation: %w", err)
	}

	if !res.Valid() {
		var finalErr error
		for _, err := range res.Errors() {
			finalErr = errors.Join(finalErr, errors.New(err.String()))
		}
		return finalErr
	}

	var stageErr error
	for _, stage := range w.Stages {
		for _, componentRef := range stage.ComponentRefs {
			if err := componentRef.Component.Validate(); err != nil {
				stageErr = errors.Join(stageErr, err)
				continue
			}
		}
	}

	return stageErr
}
