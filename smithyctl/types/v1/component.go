package v1

type (
	// ComponentType represents all the types of components that Smithy supports.
	// ENUM(unknown, target, scanner, enricher, filter, reporter)
	ComponentType string

	// Component is a binary or a script that can be used in the context of a
	// workflow to generate some useful result.
	Component struct {
		// Description describes what the component will do.
		Description string
		// Name is the component name.
		Name string
		// Parameters is the list of parameters to be supplied to the component.
		Parameters []Parameter
		// Steps is the list of steps to be supplied to the component.
		Steps []Step
		// Type represents the component type.
		Type ComponentType
	}

	// Step represents an executing step inside a Component.
	Step struct {
		// Args is the list of arguments supplied to a component.
		Args []string
		// EnvVars is the set of environment variables key:val supplied to a component.
		EnvVars map[string]string
		// Name is the step name.
		Name string
		// Executable is the path to the entrypoint to run the component.
		Executable string
		// Images is the docker image to be run for this component.
		Image string
		// Script will be deprecated after rewriting all components.
		Script string
	}
)
