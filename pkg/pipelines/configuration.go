package pipelines

import (
	"context"

	"github.com/go-errors/errors"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	kustomizetypes "sigs.k8s.io/kustomize/api/types"

	"github.com/smithy-security/smithy/pkg/manifests"
)

// ResolveBase checks the resources section to find the base pipeline, If its
// not listed, default ones will be used.
func ResolveBase(ctx context.Context, kustomizationDir string, kustomization kustomizetypes.Kustomization) (*tektonv1beta1api.Pipeline, error) {
	if len(kustomization.Resources) > 1 {
		return nil, errors.Errorf("there should be at most 2 base resources: a pipeline and a task")
	}

	if len(kustomization.Resources) == 0 {
		return BasePipeline.DeepCopy(), nil
	}

	return manifests.LoadTektonV1Beta1Pipeline(ctx, kustomizationDir, kustomization.Resources[0])
}
