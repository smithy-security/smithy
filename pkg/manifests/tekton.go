package manifests

import (
	"context"

	"github.com/go-errors/errors"
	tektonv1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

// LoadTektonV1Beta1Task loads a tektonV1Beta1 Task object from a path
func LoadTektonV1Beta1Task(ctx context.Context, configurationDir, pathOrURI string) (*tektonv1beta1.Task, error) {
	obj, gKV, err := LoadK8sManifest(ctx, configurationDir, pathOrURI, "task.yaml")
	if err != nil {
		return nil, err
	}

	task, isATask := obj.(*tektonv1beta1.Task)
	if !isATask {
		return nil, errors.Errorf("object loaded is not a task: %v", gKV)
	}
	return task, nil
}

// LoadTektonV1Beta1Pipeline loads a tektonV1Beta1 Pipeline object from a path
func LoadTektonV1Beta1Pipeline(ctx context.Context, configurationDir, pathOrURI string) (*tektonv1beta1.Pipeline, error) {
	obj, gKV, err := LoadK8sManifest(ctx, configurationDir, pathOrURI, "pipeline.yaml")
	if err != nil {
		return nil, err
	}

	pipeline, isAPipeline := obj.(*tektonv1beta1.Pipeline)
	if !isAPipeline {
		return nil, errors.Errorf("object loaded is not a pipeline: %v", gKV)
	}
	return pipeline, nil
}
