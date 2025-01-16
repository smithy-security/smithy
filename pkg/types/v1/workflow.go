package v1

type (
	// Workflow represents a combination of
	Workflow struct {
		// Description described what the workflow is configured for.
		Description string
		// Name is the name of the workflow.
		Name string
		// Stages contains the stages to be applied by the workflow.
		Stages []Stage
	}

	// Stage is a group of Components that can be executed in parallel during in
	// the context of a Workflow Instance.
	Stage struct {
		// ComponentRefs contains the list of component references attached to this stage.
		ComponentRefs []ComponentRef
	}

	// ComponentRef represents a reference to a component along with some overrides
	// that the user needs to declare.
	ComponentRef struct {
		// Component represents the linked component.
		Component Component
		// Overrides contains first later of parameter overrides for this component.
		Overrides []Parameter
	}
)
