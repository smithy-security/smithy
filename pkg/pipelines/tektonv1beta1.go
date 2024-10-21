package pipelines

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-errors/errors"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/smithy-security/smithy/pkg/components"
	"github.com/smithy-security/smithy/pkg/k8s"
)

var (
	// ErrNoComponentsInKustomization is returned when a kustomization has no
	// components listed
	ErrNoComponentsInKustomization = errors.New("no components listed in kustomization")
	// ErrNoTasks is returned when no tasks are provided to the Tekton backend
	ErrNoTasks = errors.New("no tasks provided")
	// ErrNotResolved is returned when a component that has not been resolved
	// is passed to the Orchestrator
	ErrNotResolved = errors.New("component has not been resolved")
)

// NewTektonV1Beta1Orchestrator returns an Orchestrator implementation for TektonV1Beta1
func NewTektonV1Beta1Orchestrator(clientset k8s.ClientInterface, namespace string) Orchestrator[*tektonv1beta1api.Pipeline] {
	return k8sOrchestrator{
		clientset: clientset,
		namespace: namespace,
	}
}

type k8sOrchestrator struct {
	clientset k8s.ClientInterface
	namespace string
}

// getRepositoryTasks checks all the Tasks of the namespace and creates a
// registry based on their Helm release name.
func (k k8sOrchestrator) getRepositoryTasks(ctx context.Context) (map[string]map[string]tektonv1beta1api.Task, error) {
	taskList, err := k.clientset.
		Tasks(k.namespace).
		List(ctx, metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(
				&metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/managed-by": "Helm",
					},
				},
			),
		})
	if err != nil {
		return nil, errors.Errorf("could not resolve tasks of Helm registry: %w", err)
	}

	helmManagedComponents := map[string]map[string]tektonv1beta1api.Task{}
	for _, task := range taskList.Items {
		// if the task is not annotated then it's not managed by Helm
		helmRegistry, exists := task.Annotations["meta.helm.sh/release-name"]
		if !exists {
			continue
		}

		tasksInHelmRelease, exists := helmManagedComponents[helmRegistry]
		if !exists {
			tasksInHelmRelease = map[string]tektonv1beta1api.Task{}
			helmManagedComponents[helmRegistry] = tasksInHelmRelease
		}
		tasksInHelmRelease[task.Name] = task
	}

	return helmManagedComponents, nil
}

// Prepare will scan the cluster for all Helm managed Tasks and will deploy all
// Tasks managed in a custom way.
func (k k8sOrchestrator) Prepare(ctx context.Context, pipelineComponents []components.Component) error {
	var err error

	helmManagedComponents, err := k.getRepositoryTasks(ctx)
	if err != nil {
		return errors.Errorf("could not scan namespace for Helm managed components: %w", err)
	}

	for i, pipelineComponent := range pipelineComponents {
		if pipelineComponent.OrchestrationType == components.OrchestrationTypeNaive {
			if !pipelineComponent.Resolved || pipelineComponent.Manifest == nil {
				return ErrNotResolved
			}

			err := components.ProcessTasks(pipelineComponent.Manifest.(*tektonv1beta1api.Task))
			if err != nil {
				return err
			}

			err = k.clientset.Apply(ctx, pipelineComponent.Manifest, k.namespace, false)
			if err != nil {
				return err
			}
		} else if pipelineComponent.OrchestrationType == components.OrchestrationTypeExternalHelm {
			componentSet, exists := helmManagedComponents[pipelineComponent.Repository]
			if !exists {
				return errors.Errorf("no Helm release with name %s is deployed in the namespace %s (%s)", pipelineComponent.Repository, k.namespace, pipelineComponent.Name)
			}

			component, exists := componentSet[pipelineComponent.Name]
			if !exists {
				return errors.Errorf("component %s/%s could not be found in the cluster", pipelineComponent.Repository, pipelineComponent.Name)
			}

			pipelineComponent.Manifest = &component
			componentTypeLabel, exists := component.Labels[components.LabelKey]
			if !exists {
				return errors.Errorf("%s: task does not have a component type label", component.Name)
			}

			componentType, err := components.ParseComponentType(componentTypeLabel)
			if err != nil {
				return errors.Errorf("%s: task has wrong component type: %w", component.Name, err)
			}
			pipelineComponent.Type = componentType
			pipelineComponent.Resolved = true
			pipelineComponents[i] = pipelineComponent
		}
	}

	return nil
}

// Deploy will generate a pipeline based on the components provided
func (k k8sOrchestrator) Deploy(ctx context.Context, basePipeline *tektonv1beta1api.Pipeline, pipelineComponents []components.Component, suffix string, dryRun bool) (*tektonv1beta1api.Pipeline, error) {
	if len(pipelineComponents) == 0 {
		return nil, errors.Errorf("could not generate pipeline: %w", ErrNoTasks)
	}

	taskList := []*tektonv1beta1api.Task{}
	for _, pipelineComponent := range pipelineComponents {
		taskList = append(taskList, pipelineComponent.Manifest.(*tektonv1beta1api.Task))
	}

	// Sort tasks based on their component type
	slices.SortFunc(taskList, func(a *tektonv1beta1api.Task, b *tektonv1beta1api.Task) int {
		componentTypeA := components.MustParseComponentType(a.Labels[components.LabelKey])
		componentTypeB := components.MustParseComponentType(b.Labels[components.LabelKey])
		return components.ADifferenceFromB(componentTypeA, componentTypeB)
	})

	pipeline, err := generatePipeline(basePipeline, taskList)
	if err != nil && dryRun {
		return pipeline, err
	}

	return pipeline, k.clientset.Apply(ctx, pipeline, k.namespace, false)
}

// generatePipeline will generate a Tekton pipeline based on list of tasks
// provided. it is assumed that the tasks are sorted based on the component
// type, with the base component being the first one and the last components
// being the consumers. the function will mainly work on generating the
// parameter lists for the pipeline. each Tekton pipeline has a list of
// parameters that it can accept using a pipelinerun object. These parameters
// are then injected into the tasks by referencing them in the pipeline task
// list.
//
//revive:disable:cyclomatic Makes no sense to split this up
//revive:disable:cognitive-complexity Makes no sense to split this up
func generatePipeline(pipeline *tektonv1beta1api.Pipeline, taskList []*tektonv1beta1api.Task) (*tektonv1beta1api.Pipeline, error) {
	pipelineWorkspaces := map[string]struct{}{}
	anchors := map[components.ComponentType][]string{}

	for _, task := range taskList {
		componentTypeStr := task.Labels[components.LabelKey]
		componentType, err := components.ParseComponentType(componentTypeStr)
		if err != nil {
			return nil, errors.Errorf("%s: task has invalid component type: %w", task.Name, err)
		}

		anchors[componentType] = append(anchors[componentType], task.Name)

		// add task to pipeline tasks
		pipelineTask := tektonv1beta1api.PipelineTask{
			Name: task.Name,
			TaskRef: &tektonv1beta1api.TaskRef{
				Name: task.Name,
			},
		}

		// add task's workspaces to pipeline workspaces
		// make sure to propagate the `optional` field
		for _, ws := range task.Spec.Workspaces {
			if _, inserted := pipelineWorkspaces[ws.Name]; !inserted {
				pipeline.Spec.Workspaces = append(pipeline.Spec.Workspaces, tektonv1beta1api.PipelineWorkspaceDeclaration{
					Name:     ws.Name,
					Optional: ws.Optional,
				})
				pipelineWorkspaces[ws.Name] = struct{}{}
			}
			pipelineTask.Workspaces = append(pipelineTask.Workspaces, tektonv1beta1api.WorkspacePipelineTaskBinding{
				Name:      ws.Name,
				Workspace: ws.Name,
			})
		}

		// add the task's parameters to the pipeline's parameters and
		// reference them in the pipeline task parameters
		pipelineTask.Params = tektonv1beta1api.Params{}

		for _, param := range task.Spec.Params {
			// unless we skip these parameters, we will end up adding them to
			// the pipeline parameters over and over again. so we leave them
			// for the end of the method.
			if param.Name == "smithy_scan_id" || param.Name == "smithy_scan_start_time" || param.Name == "smithy_scan_tags" {
				continue
			}

			newPipelineParam := tektonv1beta1api.Param{
				Name:  param.Name,
				Value: tektonv1beta1api.ParamValue{},
			}

			if param.Name == "anchors" {
				anchorTargetComponentType := components.GetPrevious(componentType)
				values := []string{}

				// get all the tasks that should be finished before this one starts
				for _, anchorTarget := range anchors[anchorTargetComponentType] {
					values = append(values, fmt.Sprintf("$(tasks.%s.results.anchor)", anchorTarget))
				}

				newPipelineParam.Value.ArrayVal = values
				newPipelineParam.Value.Type = tektonv1beta1api.ParamTypeArray
			} else {
				newPipelineParam.Value.Type = param.Type

				switch param.Type {
				case tektonv1beta1api.ParamTypeArray:
					newPipelineParam.Value.ArrayVal = []string{fmt.Sprintf("$(params.%s)", param.Name)}
				case tektonv1beta1api.ParamTypeString:
					newPipelineParam.Value.StringVal = fmt.Sprintf("$(params.%s)", param.Name)
				default:
					return nil, errors.Errorf("parameter %s of task %s has no type set or is of unsupported type object", param.Name, task.Name)
				}

				// add parameter to pipeline parameters
				pipeline.Spec.Params = append(pipeline.Spec.Params, tektonv1beta1api.ParamSpec{
					Name:        param.Name,
					Type:        param.Type,
					Description: param.Description,
					Default:     param.Default,
				})
			}

			// add pipeline parameter to parameters passed to the task
			pipelineTask.Params = append(pipelineTask.Params, newPipelineParam)
		}

		if err = addSmithyParamsToTask(&pipelineTask, anchors[components.Base][0], task); err != nil {
			return nil, err
		}

		// add task reference to pipeline's tasks
		pipeline.Spec.Tasks = append(pipeline.Spec.Tasks, pipelineTask)
	}

	return pipeline, nil
}
