package pipelines

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kustomizetypes "sigs.k8s.io/kustomize/api/types"

	"github.com/smithy-security/smithy/pkg/components"
	"github.com/smithy-security/smithy/pkg/k8s/fake"
	"github.com/smithy-security/smithy/pkg/manifests"
)

func TestResolveKustomizationResourceBase(t *testing.T) {
	testCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	basePipelineFromFile, err := manifests.LoadTektonV1Beta1Pipeline(testCtx, ".", "../../components/base")
	require.NoError(t, err)

	BasePipeline.Labels = map[string]string{"TestResolveKustomizationResourceBases": "bla"}
	defer func() {
		BasePipeline.Labels = nil
		BaseTask.Labels = nil
	}()

	testCases := []struct {
		name             string
		kustomization    *kustomizetypes.Kustomization
		expectedPipeline *tektonv1beta1api.Pipeline
		expectedErr      error
	}{
		{
			name: "no base pipeline in the kustomization",
			kustomization: &kustomizetypes.Kustomization{
				NameSuffix: "-cyberdyne-card-processing",
				Resources:  []string{},
			},
			expectedPipeline: BasePipeline,
		},
		{
			name: "success",
			kustomization: &kustomizetypes.Kustomization{
				NameSuffix: "-cyberdyne-card-processing",
				Resources: []string{
					"../../components/base/pipeline.yaml",
				},
			},
			expectedPipeline: basePipelineFromFile,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runCtx, cancel := context.WithCancel(testCtx)
			defer cancel()

			basePipeline, err := ResolveBase(runCtx, ".", *testCase.kustomization)
			require.ErrorIs(t, err, testCase.expectedErr)
			require.Equal(t, testCase.expectedPipeline, basePipeline)
		})
	}
}

func TestComponentPrepareChecks(t *testing.T) {
	fakeClient, err := fake.NewFakeTypedClient(&tektonv1beta1api.Task{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Task",
			APIVersion: tektonv1beta1api.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "producer-aggregator",
			Namespace: "smithy",
			Annotations: map[string]string{
				"meta.helm.sh/release-name": "smithy-security-oss-components",
			},
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":            "Helm",
				"v1.smithy.smithy-security.com/component": components.ProducerAggregator.String(),
			},
		},
		Spec: tektonv1beta1api.TaskSpec{
			Params: tektonv1beta1api.ParamSpecs{
				tektonv1beta1api.ParamSpec{
					Name: "anchors",
					Type: tektonv1beta1api.ParamTypeArray,
				},
			},
			Workspaces: []tektonv1beta1api.WorkspaceDeclaration{
				{
					Name: "output",
				},
			},
		},
	})
	require.NoError(t, err)
	orchestrator := k8sOrchestrator{
		clientset: fakeClient,
		namespace: "smithy",
	}

	componentList := []components.Component{
		{
			Name:              "producer-aggregator",
			Reference:         "pkg:helm/smithy-security-oss-components/producer-aggregator",
			Repository:        "smithy-security-oss-components",
			Type:              components.ProducerAggregator,
			OrchestrationType: components.OrchestrationTypeExternalHelm,
		},
	}
	require.NoError(t, orchestrator.Prepare(context.Background(), componentList))
	require.True(t, componentList[0].Resolved)
	require.NotNil(t, componentList[0].Manifest)

	componentList = []components.Component{
		{
			Name:              "producer-golang-gosec",
			Reference:         "../../components/producers/golang-gosec",
			OrchestrationType: components.OrchestrationTypeNaive,
			Resolved:          true,
			Manifest:          componentList[0].Manifest,
		},
	}
	require.NoError(t, orchestrator.Prepare(context.Background(), componentList))

	componentList[0].Resolved = false
	require.ErrorIs(t, orchestrator.Prepare(context.Background(), componentList), ErrNotResolved)

	componentList[0].Resolved = true
	componentList[0].Manifest = nil
	require.ErrorIs(t, orchestrator.Prepare(context.Background(), componentList), ErrNotResolved)
}
