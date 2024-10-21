package pipelines

import (
	"fmt"

	tektonv1beta1api "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"

	"github.com/smithy-security/smithy/pkg/components"
)

// func renameParameterRef(oldVal string, newParameterNames map[string]string) string {
// 	if !strings.HasPrefix(oldVal, "$(params.") {
// 		return oldVal
// 	}
// 	oldParamRef := strings.Split(oldVal, "$(params.")[1]
// 	// remove last parentheses
// 	oldParamRef = oldParamRef[:len(oldParamRef)-1]
// 	return fmt.Sprintf("$(params.%s)", newParameterNames[oldParamRef])
// }

// fixTaskPrefixSuffix adds a prefix and a suffix to the name of the task and all the task
// parameters. Having task parameters prefixed with the same name as the task itself, helps
// users figure out more easily which parameters configure what.
// func fixTaskPrefixSuffix(task tektonV1Beta1.Task, prefix, suffix string) {
// 	// keep track of renamings so that we can also fix the environment variables
// 	// referencing the parameters
// 	newParameterNames := map[string]string{}
// 	for _, param := range task.Spec.Parameters {
// 		oldParamName := param.Name
// 		paramNameChunks := strings.Split(param.Name, task.Name)
// 		param.Name = prefix + task.Name + suffix + paramNameChunks[1]
// 		newParameterNames[oldParamName] = param.Name
// 	}
// 	// fix references to parameters in step env vars and images
// 	for _, step := range task.Spec.Steps {
// 		for _, env := range step.Env {
// 			env.Value = renameParameterRef(env.Value, newParameterNames)
// 		}
// 		step.Image = renameParameterRef(step.Image, newParameterNames)
// 	}
// 	task.Name = prefix + task.Name + suffix
// }

func addSmithyParamsToTask(pipelineTask *tektonv1beta1api.PipelineTask, baseTaskName string, task *tektonv1beta1api.Task) error {
	isProducer, err := components.LabelValueOneOf(task.Labels, components.Producer)
	if err != nil {
		return err
	}
	if !isProducer {
		return nil
	}

	pipelineTask.Params = append(pipelineTask.Params, []tektonv1beta1api.Param{
		{
			Name: "smithy_scan_id",
			Value: tektonv1beta1api.ParamValue{
				Type:      tektonv1beta1api.ParamTypeString,
				StringVal: fmt.Sprintf("$(tasks.%s.results.smithy-scan-id)", baseTaskName),
			},
		},
		{
			Name: "smithy_scan_start_time",
			Value: tektonv1beta1api.ParamValue{
				Type:      tektonv1beta1api.ParamTypeString,
				StringVal: fmt.Sprintf("$(tasks.%s.results.smithy-scan-start-time)", baseTaskName),
			},
		},
		{
			Name: "smithy_scan_tags",
			Value: tektonv1beta1api.ParamValue{
				Type:      tektonv1beta1api.ParamTypeString,
				StringVal: fmt.Sprintf("$(tasks.%s.results.smithy-scan-tags)", baseTaskName),
			},
		},
	}...)

	return nil
}
