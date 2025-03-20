package component_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
)

func TestParseComponentSpec(t *testing.T) {
	parser := component.NewSpecParser()

	for _, tt := range []struct {
		testCase          string
		componentSpecPath string
		isValid           bool
	}{
		{
			testCase:          "it should return an error because the path does not exist",
			componentSpecPath: "/some/path/that/does/not/exist",
			isValid:           false,
		},
		{
			testCase:          "it should return an error because the yaml spec is invalid",
			componentSpecPath: "testdata/package/targets/invalid/component.yaml",
			isValid:           false,
		},
		{
			testCase:          "it should return an error because the yml spec is invalid",
			componentSpecPath: "testdata/package/targets/invalid/component.yml",
			isValid:           false,
		},
		{
			testCase:          "it should correctly parse the yaml spec",
			componentSpecPath: "testdata/package/targets/valid/component.yaml",
			isValid:           true,
		},
		{
			testCase:          "it should correctly parse the yml spec",
			componentSpecPath: "testdata/package/targets/valid/component.yml",
			isValid:           true,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			_, err := parser.Parse(tt.componentSpecPath)
			if tt.isValid {
				require.NoError(t, err)
				return
			}
			assert.Error(t, err)
		})
	}
}
