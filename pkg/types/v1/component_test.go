package v1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

func TestComponent_Validate(t *testing.T) {
	t.Run("it should fail the validation for an invalid component", func(t *testing.T) {
		component := v1.Component{
			Description: "I enrich this and that",
			Steps:       make([]v1.Step, 0),
			Type:        v1.ComponentTypeEnricher,
		}

		require.Error(t, component.Validate())
	})
	t.Run("it should pass the validation for a valid component", func(t *testing.T) {
		component := v1.Component{
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
			Parameters: []v1.Parameter{
				{
					Name:  "cool_parameter",
					Type:  "string",
					Value: "parameter1",
				},
				{
					Name:  "someparameter",
					Type:  "string",
					Value: "parameter2",
				},
			},
			Type: v1.ComponentTypeEnricher,
			Name: "my-enricher",
		}

		require.NoError(t, component.Validate())
	})
}
