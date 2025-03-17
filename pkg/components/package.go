package components

import (
	"context"
	stderrors "errors"
	"os"
	"path"
	"path/filepath"

	"github.com/go-errors/errors"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/smithy-security/smithy/pkg/manifests"
)

var (
	// ErrCouldNotStatPath is returned when the path to the components doesn't
	// exist or is inaccesbile
	ErrCouldNotStatPath = errors.New("could not stat path")
	// ErrNotADirectory is returned when the path is not pointing to a
	// directory
	ErrNotADirectory = errors.New("path is not a directory")
)

// Package explores the components folder provided and gathers all the Tekton
// Tasks into one Helm chart.
func Package(ctx context.Context, name, componentFolder string, smithyVersion string, chartVersion string) (err error) {
	fs, err := os.Stat(componentFolder)
	if err != nil {
		return errors.Errorf("%s: could not stat: %w", componentFolder, err)
	}

	if !fs.IsDir() {
		return errors.Errorf("%s: path is not a directory", componentFolder)
	}

	tempFolder, err := os.MkdirTemp("", "smithy-helm")
	if err != nil {
		return errors.Errorf("there was an error while trying to create temp directory: %w", err)
	}
	defer func() {
		err = stderrors.Join(err, os.RemoveAll(tempFolder))
	}()

	taskPaths, err := GatherTasks(componentFolder)
	if err != nil {
		return errors.Errorf("could not discover tasks: %w", err)
	}

	taskList, err := LoadTasks(ctx, taskPaths)
	if err != nil {
		return errors.Errorf("could not load tasks: %w", err)
	}

	if err = ProcessTasks(taskList...); err != nil {
		return errors.Errorf("could not process tasks: %w", err)
	}

	if err = constructPackage(tempFolder, name, chartVersion, smithyVersion, taskList); err != nil {
		return errors.Errorf("could not generate Helm manifests: %w", err)
	}

	taskChart, err := loader.LoadDir(tempFolder)
	if err != nil {
		return errors.Errorf("could not load tasks into a Helm chart: %w", err)
	}

	_, err = chartutil.Save(taskChart, ".")
	if err != nil {
		return errors.Errorf("could not create package tar file: %w", err)
	}

	return nil
}

func LoadTasks(ctx context.Context, taskPaths []string) ([]*tektonv1beta1api.Task, error) {
	taskList := []*tektonv1beta1api.Task{}
	for _, taskFile := range taskPaths {
		task, err := manifests.LoadTektonV1Beta1Task(ctx, ".", taskFile)
		if err != nil {
			return nil, errors.Errorf("%s: not a valid manifest: %w", taskFile, err)
		}
		taskList = append(taskList, task)
	}
	return taskList, nil
}

// ProcessTasks adds anchors, environment variables, parameters and any
// extra infrastructure required for a Task to become a useful part of a
// pipeline.
func ProcessTasks(taskList ...*tektonv1beta1api.Task) error {
	for _, task := range taskList {
		if err := addAnchorParameter(task); err != nil {
			return err
		}
		if err := addAnchorResult(task); err != nil {
			return err
		}
		if err := addEnvVarsToTask(task); err != nil {
			return err
		}
	}

	return nil
}

// constructPackage creates a templates folder with all the discovered tasks
// in at the designated Path, along with a Chart file
//
//revive:disable:cyclomatic High complexity score but easy to understand
//revive:disable:cognitive-complexity High complexity score but easy to understand
func constructPackage(helmFolder, name, version, smithyVersion string, taskList []*tektonv1beta1api.Task) error {
	if err := os.Mkdir(path.Join(helmFolder, "templates"), os.ModePerm); err != nil {
		return errors.Errorf("could not create templates folder")
	}

	tasksFilePath := path.Join(helmFolder, "templates", "tasks.yaml")
	tasksFile, err := os.OpenFile(tasksFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return errors.Errorf("could not create tasks file: %w", err)
	}

	for _, task := range taskList {
		if err = manifests.TektonV1Beta1ObjEncoder.Encode(task, tasksFile); err != nil {
			return errors.Errorf("could not store task %s: %w", task.Name, err)
		}

		if _, err = tasksFile.WriteString("---\n"); err != nil {
			return errors.Errorf("%s: could not write to file: %w", tasksFilePath, err)
		}
	}

	chartFile := path.Join(helmFolder, "Chart.yaml")
	_, err = os.Create(chartFile)
	if err != nil {
		return errors.Errorf("could not create Chart file: %w", err)
	}

	helmChart := chart.Metadata{
		APIVersion: chart.APIVersionV2,
		Name:       name,
		Version:    version,
		AppVersion: smithyVersion,
	}

	if err = helmChart.Validate(); err != nil {
		return errors.Errorf("there was an issue generating the Helm metadata: %w", err)
	}

	helmMetadataBytes, err := yaml.Marshal(helmChart)
	if err != nil {
		return errors.Errorf("could not marshal Helm matadata: %w", err)
	}

	err = os.WriteFile(chartFile, helmMetadataBytes, os.ModeAppend)
	if err != nil {
		return errors.Errorf("could not write ")
	}

	return nil
}

// GatherTasks returns the paths of all the Tekton Tasks discovered
//
//revive:disable:cognitive-complexity High complexity score but easy to understand
func GatherTasks(folder string) ([]string, error) {
	taskPaths := []string{}

	for _, componentType := range []string{"base", "sources", "producers", "enrichers", "consumers"} {
		componentsFolder := path.Join(folder, componentType)
		stat, err := os.Stat(componentsFolder)
		if err != nil {
			continue
		}

		if !stat.IsDir() {
			return nil, errors.Errorf("%s: %w", componentsFolder, ErrNotADirectory)
		}

		err = filepath.Walk(componentsFolder, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return errors.Errorf("%s: %w", path, err)
			}

			if info == nil {
				return errors.Errorf("path %s doesn't exist", path)
			}

			if !info.IsDir() && info.Name() == "task.yaml" {
				taskPaths = append(taskPaths, path)
			}
			return nil
		})

		if err != nil {
			return nil, errors.Errorf("there was an error while gathering tasks: %w", err)
		}
	}
	return taskPaths, nil
}

// addAnchorResult adds an `anchor` entry to the results section of a Task.
// This helps reduce the amount of boilerplate needed to be written by a user
// to introduce a component. The base task doesn't need an anchor because its
// output it a dependency for the consumer tasks.
func addAnchorResult(task *tektonv1beta1api.Task) error {
	hasLabel, err := LabelValueOneOf(task.Labels, Consumer, Base)
	if err != nil {
		return errors.Errorf("%s: %w", task.Name, err)
	}
	if hasLabel {
		return nil
	}
	for _, step := range task.Spec.Steps {
		if step.Name == "anchor" {
			return nil
		}
	}
	task.Spec.Results = append(task.Spec.Results, tektonv1beta1api.TaskResult{
		Name:        "anchor",
		Description: "An anchor to allow other tasks to depend on this task.",
	})

	task.Spec.Steps = append(task.Spec.Steps, tektonv1beta1api.Step{
		Name:   "anchor",
		Image:  "docker.io/busybox",
		Script: "echo \"$(context.task.name)\" > \"$(results.anchor.path)\"",
	})

	return nil
}

// addAnchorParameter adds an `anchors` entry to the parameters of a Task. This
// entry will then be filled in the pipeline with the anchors of the tasks that
// this task depends on.
func addAnchorParameter(task *tektonv1beta1api.Task) error {
	componentType, err := ParseComponentType(task.Labels[LabelKey])
	if err != nil {
		return errors.Errorf("%s: %w", task.Name, err)
	}
	if AGreaterThanB(Producer, componentType) {
		return nil
	}

	for _, param := range task.Spec.Params {
		if param.Name == "anchors" {
			return nil
		}
	}
	task.Spec.Params = append(task.Spec.Params, tektonv1beta1api.ParamSpec{
		Name:        "anchors",
		Description: "A list of tasks that this task depends on",
		Type:        "array",
		Default: &tektonv1beta1api.ParamValue{
			Type: tektonv1beta1api.ParamTypeArray,
		},
	})

	return nil
}

// addParamsAndEnvVars will add parameters and environment variables to the producer task that will
// allow it to pick the start time, pipeline UUID and any tags that have been given as parameter to
// the pipeline so that the issues discovered can be annotated with these values.
func addEnvVarsToTask(task *tektonv1beta1api.Task) error {
	componentType, err := ParseComponentType(task.Labels[LabelKey])
	if err != nil {
		return errors.Errorf("%s: %w", task.Name, err)
	}
	if componentType != Producer {
		return nil
	}
	scanIDFound := false
	scanStartTimeFound := false
	scanTagsFound := false

	for _, param := range task.Spec.Params {
		if param.Name == "smithy_scan_id" {
			scanIDFound = true
		} else if param.Name == "smithy_scan_start_time" {
			scanStartTimeFound = true
		} else if param.Name == "smithy_scan_tags" {
			scanTagsFound = true
		}
	}
	if !scanIDFound {
		task.Spec.Params = append(task.Spec.Params, tektonv1beta1api.ParamSpecs{
			{
				Name: "smithy_scan_id",
				Type: tektonv1beta1api.ParamTypeString,
			},
		}...)
	}
	if !scanStartTimeFound {
		task.Spec.Params = append(task.Spec.Params, tektonv1beta1api.ParamSpecs{
			{
				Name: "smithy_scan_start_time",
				Type: tektonv1beta1api.ParamTypeString,
			},
		}...)
	}
	if !scanTagsFound {
		task.Spec.Params = append(task.Spec.Params, tektonv1beta1api.ParamSpecs{
			{
				Name: "smithy_scan_tags",
				Type: tektonv1beta1api.ParamTypeString,
			},
		}...)
	}

	scanIDFound = false
	scanStartTimeFound = false
	scanTagsFound = false
	for i, step := range task.Spec.Steps {
		for _, envVar := range step.Env {
			if envVar.Name == "SMITHY_SCAN_TIME" {
				scanStartTimeFound = true
			} else if envVar.Name == "SMITHY_SCAN_ID" {
				scanIDFound = true
			} else if envVar.Name == "SMITHY_SCAN_TAGS" {
				scanTagsFound = true
			}
		}
		if !scanStartTimeFound {
			step.Env = append(step.Env, []corev1.EnvVar{
				{
					Name:  "SMITHY_SCAN_TIME",
					Value: "$(params.smithy_scan_start_time)",
				},
			}...)
		}
		if !scanIDFound {
			step.Env = append(step.Env, []corev1.EnvVar{
				{
					Name:  "SMITHY_SCAN_ID",
					Value: "$(params.smithy_scan_id)",
				},
			}...)
		}
		if !scanTagsFound {
			step.Env = append(step.Env, []corev1.EnvVar{
				{
					Name:  "SMITHY_SCAN_TAGS",
					Value: "$(params.smithy_scan_tags)",
				},
			}...)
		}

		task.Spec.Steps[i] = step
	}
	return nil
}
