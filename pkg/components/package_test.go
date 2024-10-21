package components

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"

	"github.com/smithy-security/smithy/pkg/manifests"
)

func TestGatherTasks(t *testing.T) {
	taskPaths, err := GatherTasks("testdata")
	require.NoError(t, err)
	require.EqualValues(t,
		[]string{
			"testdata/base/task.yaml",
			"testdata/sources/git/task.yaml",
			"testdata/producers/aggregator/task.yaml",
			"testdata/producers/cdxgen/task.yaml",
			"testdata/enrichers/aggregator/task.yaml",
			"testdata/consumers/arangodb/task.yaml",
		},
		taskPaths,
	)

	taskPaths, err = GatherTasks("..")
	require.NoError(t, err)
	require.Empty(t, taskPaths)
}

func TestCreateHelmPackage(t *testing.T) {
	smithyVersion := "v0.10.0"
	semVer := "0.10.0"
	taskList, err := LoadTasks(
		context.Background(),
		[]string{
			"testdata/base/task.yaml",
			"testdata/sources/git/task.yaml",
			"testdata/producers/cdxgen/task.yaml",
			"testdata/producers/aggregator/task.yaml",
			"testdata/enrichers/aggregator/task.yaml",
			"testdata/consumers/arangodb/task.yaml",
		},
	)
	require.NoError(t, err)

	require.NoError(t, ProcessTasks(taskList...))
	require.Len(t, taskList[2].Spec.Steps[1].Env, 3)
	require.Equal(t, "SMITHY_SCAN_TIME", taskList[2].Spec.Steps[1].Env[0].Name)
	require.Equal(t, "SMITHY_SCAN_ID", taskList[2].Spec.Steps[1].Env[1].Name)
	require.Equal(t, "SMITHY_SCAN_TAGS", taskList[2].Spec.Steps[1].Env[2].Name)
	paramLen := len(taskList[2].Spec.Params)
	require.Equal(t, taskList[2].Spec.Params[paramLen-4].Name, "anchors")
	require.Equal(t, taskList[2].Spec.Params[paramLen-3].Name, "smithy_scan_id")
	require.Equal(t, taskList[2].Spec.Params[paramLen-2].Name, "smithy_scan_start_time")
	require.Equal(t, taskList[2].Spec.Params[paramLen-1].Name, "smithy_scan_tags")

	helmFolder := t.TempDir()
	require.NoError(t, constructPackage(helmFolder, "smithy-security-oss-components", semVer, smithyVersion, taskList))
	require.FileExists(t, path.Join(helmFolder, "Chart.yaml"))
	chartFileContents, err := os.ReadFile(path.Join(helmFolder, "Chart.yaml"))
	require.NoError(t, err)
	require.Equal(
		t,
		fmt.Sprintf(`apiVersion: v2
appVersion: %s
name: smithy-security-oss-components
version: %s
`, smithyVersion, semVer),
		string(chartFileContents),
	)
	require.FileExists(t, path.Join(path.Join(helmFolder, "templates", "tasks.yaml")))
	taskTemplateContents, err := os.ReadFile(path.Join(helmFolder, "templates", "tasks.yaml"))
	require.NoError(t, err)

	for _, rawTask := range strings.Split(string(taskTemplateContents), "---\n") {
		// the Split function returns an empty string at the end
		if rawTask == "" {
			continue
		}
		obj, gKV, err := manifests.K8sObjDecoder.Decode([]byte(rawTask), nil, nil)
		require.NoError(t, err)
		require.Equal(t, *gKV, tektonv1beta1api.SchemeGroupVersion.WithKind("Task"))

		task, isATask := obj.(*tektonv1beta1api.Task)
		require.True(t, isATask)

		baseOrSource, err := LabelValueOneOf(task.Labels, Base, Source)
		require.NoError(t, err)

		if baseOrSource {
			goto checkSteps
		}

		for _, param := range task.Spec.Params {
			if param.Name == "anchors" {
				goto checkSteps
			}
		}
		t.Fatalf("task %s has no anchor parameter", task.Name)

	checkSteps:
		baseOrConsumer, err := LabelValueOneOf(task.Labels, Base, Consumer)
		require.NoError(t, err)
		if baseOrConsumer {
			continue
		}

		require.Equal(t, "anchor", task.Spec.Steps[len(task.Spec.Steps)-1].Name, "task %s has no anchor step", task.Name)
	}
}

func TestProcessTasksAnchorsEnvExist(t *testing.T) {
	taskList, err := LoadTasks(
		context.Background(),
		[]string{
			"testdata/base/task.yaml",
			"testdata/sources/git/task.yaml",
			"testdata/producers/cdxgen/task.yaml",
			"testdata/producers/aggregator/task.yaml",
			"testdata/enrichers/aggregator/task.yaml",
			"testdata/consumers/arangodb/task.yaml",
		},
	)
	require.NoError(t, err)

	// add anchors and env vars once
	require.NoError(t, ProcessTasks(taskList...))

	// ensure anchors have been added once
	requireAnchors(t, taskList)

	// ensure envvars have been added once
	requireEnvVars(t, taskList)

	// add anchors and env vars again
	require.NoError(t, ProcessTasks(taskList...))

	// ensure anchors have been added once
	requireAnchors(t, taskList)
	requireEnvVars(t, taskList)
}

//revive:disable:cyclomatic High complexity score but easy to understand
//revive:disable:cognitive-complexity High complexity score but easy to understand
func requireAnchors(t *testing.T, taskList []*tektonv1beta1api.Task) {
	for _, task := range taskList {
		require.NotEmpty(t, task.Spec.Steps)
		if strings.Contains(task.Name, "base") || strings.Contains(task.Name, "git") { // base and git tasks have no anchors
			continue
		}

		anchorParamNames := []string{}
		for _, param := range task.Spec.Params {
			if param.Name == "anchors" {
				anchorParamNames = append(anchorParamNames, "anchors")
			}
		}

		anchorNames := []string{}
		for _, step := range task.Spec.Steps {
			if step.Name == "anchor" {
				anchorNames = append(anchorNames, "anchor")
			}
		}
		anchorResultNames := []string{}
		for _, result := range task.Spec.Results {
			if result.Name == "anchor" {
				anchorResultNames = append(anchorResultNames, "anchor")
			}
		}
		require.Equal(t, len(anchorParamNames), 1)

		if strings.Contains(task.Name, "consumer") {
			continue // consumers have no anchor steps
		}
		require.Equal(t, len(anchorNames), 1)
		require.Equal(t, len(anchorResultNames), 1)
	}
}

//revive:disable:cyclomatic High complexity score but easy to understand
//revive:disable:cognitive-complexity High complexity score but easy to understand
func requireEnvVars(t *testing.T, taskList []*tektonv1beta1api.Task) {
	envVars := []string{"SMITHY_SCAN_TIME", "SMITHY_SCAN_ID", "SMITHY_SCAN_TAGS"}
	params := []string{"smithy_scan_id", "smithy_scan_start_time", "smithy_scan_tags"}
	for _, task := range taskList {
		taskParams := []string{}
		if !strings.Contains(task.Name, "producer") || strings.Contains(task.Name, "aggregator") { // env vars are for producers only
			continue
		}
		for _, p := range task.Spec.Params {
			if slices.Contains(params, p.Name) {
				taskParams = append(taskParams, p.Name)
			}
		}

		require.Equalf(t, len(taskParams), len(params), "task %s has missing params", task.Name)
		for _, step := range task.Spec.Steps {
			require.NotEmptyf(t, step.Env, "task %s has no env vars", task.Name)
			stepEnvVars := []string{}
			for _, env := range step.Env {
				if slices.Contains(envVars, env.Name) {
					stepEnvVars = append(stepEnvVars, env.Name)
				}
			}
			require.Equalf(t, len(envVars), len(stepEnvVars), "task %s has env vars %#v", task.Name, stepEnvVars)
		}
	}
}
