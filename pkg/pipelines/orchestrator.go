package pipelines

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/smithy-security/smithy/pkg/components"
)

// Orchestrator represents a piece of code that orchestrates the deployment of
// components and pipelines on a backend. The backend could be a cluster with a
// Tekton operator for example, or some other system.
type Orchestrator[P runtime.Object] interface {
	// Prepare checks if the expected components are present in the cluster and
	// performs any operations to ensure that the workflow can be deployed.
	Prepare(context.Context, []components.Component) error

	// Deploy will generate a Pipeline based on the components and return it.
	// If dry run is set to false, the pipeline will also be applied to the
	// cluster.
	Deploy(context.Context, P, []components.Component, string, bool) (P, error)
}
