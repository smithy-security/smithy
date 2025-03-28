package components

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

func TestComponentResolutionFromReference(t *testing.T) {
	dereferencedComponent, err := FromReference(context.Background(), "pkg:helm/smithy-security-oss-components/producer-aggregator")
	require.NoError(t, err)
	require.Equal(t, Component{
		Name:              "producer-aggregator",
		Reference:         "pkg:helm/smithy-security-oss-components/producer-aggregator",
		Repository:        "smithy-security-oss-components",
		OrchestrationType: OrchestrationTypeExternalHelm,
	}, dereferencedComponent)

	dereferencedComponent, err = FromReference(context.Background(), "../../deprecated-components/producers/golang-gosec")
	require.NoError(t, err)
	require.Equal(t, "producer-golang-gosec", dereferencedComponent.Name)
	require.Equal(t, "../../deprecated-components/producers/golang-gosec", dereferencedComponent.Reference)
	require.Equal(t, OrchestrationTypeNaive, dereferencedComponent.OrchestrationType)
	require.Equal(t, Producer, dereferencedComponent.Type)
	require.Equal(t, true, dereferencedComponent.Resolved)
	require.NotNil(t, dereferencedComponent.Manifest)
	require.Equal(t, "anchors", dereferencedComponent.Manifest.(*tektonv1beta1api.Task).Spec.Params[1].Name)
	require.Equal(t, "anchor", dereferencedComponent.Manifest.(*tektonv1beta1api.Task).Spec.Results[0].Name)

	_, err = FromReference(context.Background(), "../../components")
	require.Error(t, err)
}
