package v1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

func TestWorkflow_Validate(t *testing.T) {
	t.Run("it should fail the validation for an invalid workflow", func(t *testing.T) {
		workflow := v1.Workflow{
			Description: "Magic component v1",
			Name:        "magic-workflow",
			Stages:      make([]v1.Stage, 0),
		}

		require.Error(t, workflow.Validate())
	})
	t.Run("it should pass the validation for a valid workflow", func(t *testing.T) {
		workflow := v1.Workflow{
			Description: "Magic component v1",
			Name:        "magic-workflow",
			Stages: []v1.Stage{
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Description: "I enrich this and that",
								Steps: []v1.Step{
									{
										Name:       "step-1",
										Executable: "/bin/app",
										Image:      "postgres:latest",
										Args:       make([]string, 0),
										EnvVars:    make(map[string]string),
									},
								},
								Parameters: make([]v1.Parameter, 0),
								Type:       v1.ComponentTypeEnricher,
								Name:       "my-enricher",
							},
						},
					},
				},
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Description: "I wait for things to happen",
								Steps: []v1.Step{
									{
										Name:       "step-1",
										Executable: "/bin/app",
										Image:      "waiter:latest",
										Args:       make([]string, 0),
										EnvVars:    make(map[string]string),
									},
								},
								Parameters: make([]v1.Parameter, 0),
								Type:       v1.ComponentTypeEnricher,
								Name:       "my-waiteer",
							},
						},
						{
							Component: v1.Component{
								Description: "I wait for things to happen",
								Steps: []v1.Step{
									{
										Name:  "step-1",
										Image: "waiter:latest",
									},
								},
								Type: v1.ComponentTypeEnricher,
								Name: "my-waiter",
							},
						},
					},
				},
			},
		}

		require.NoError(t, workflow.Validate())
	})
}
