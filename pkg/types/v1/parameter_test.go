package v1_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

func ptr[T any](v T) *T {
	return &v
}

func TestParameter(t *testing.T) {
	t.Parallel()

	const (
		encodingJSON = "json"
		encodingYAML = "yaml"
	)

	for _, tt := range []struct {
		testCase            string
		param               v1.Parameter
		encoding            string
		expectsMarshalErr   bool
		expectsUnmarshalErr bool
	}{
		{
			testCase: "it should JSON marshal correctly a non empty pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: ptr("smithy"),
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly a non empty pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: ptr("smithy"),
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: "",
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: "",
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly a non empty string",
			param: v1.Parameter{
				Name:  "non-empty-str",
				Type:  v1.ParameterTypeString,
				Value: "smithy",
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly a non empty string",
			param: v1.Parameter{
				Name:  "non-empty-str",
				Type:  v1.ParameterTypeString,
				Value: "smithy",
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an empty pointer to a string",
			param: v1.Parameter{
				Name:  "empty-str",
				Type:  v1.ParameterTypeString,
				Value: ptr(""),
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an empty pointer to a string",
			param: v1.Parameter{
				Name:  "empty-str",
				Type:  v1.ParameterTypeString,
				Value: ptr(""),
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an nil string",
			param: v1.Parameter{
				Name: "nil-str",
				Type: v1.ParameterTypeString,
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an nil string",
			param: v1.Parameter{
				Name: "nil-str",
				Type: v1.ParameterTypeString,
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly a non empty const pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-const-ptr-str",
				Type:  v1.ParameterTypeConstString,
				Value: ptr("{{.Helm.template.value}}"),
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly a non empty const pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-const-ptr-str",
				Type:  v1.ParameterTypeConstString,
				Value: ptr("{{.Helm.template.value}}"),
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an empty const pointer to a string",
			param: v1.Parameter{
				Name:  "empty-const-ptr-str",
				Type:  v1.ParameterTypeConstString,
				Value: ptr(""),
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an empty const pointer to a string",
			param: v1.Parameter{
				Name:  "empty-const-ptr-str",
				Type:  v1.ParameterTypeConstString,
				Value: ptr(""),
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly a non empty const string",
			param: v1.Parameter{
				Name:  "non-empty-const-str",
				Type:  v1.ParameterTypeConstString,
				Value: "{{.Helm.template.value}}",
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly a non empty const string",
			param: v1.Parameter{
				Name:  "non-empty-const-str",
				Type:  v1.ParameterTypeConstString,
				Value: "{{.Helm.template.value}}",
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-const-str",
				Type:  v1.ParameterTypeConstString,
				Value: "",
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-const-str",
				Type:  v1.ParameterTypeConstString,
				Value: "",
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an nil const string",
			param: v1.Parameter{
				Name: "nil-const-str",
				Type: v1.ParameterTypeConstString,
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an nil const string",
			param: v1.Parameter{
				Name: "nil-const-str",
				Type: v1.ParameterTypeConstString,
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly a non empty list string",
			param: v1.Parameter{
				Name:  "non-empty-list-str",
				Type:  v1.ParameterTypeListString,
				Value: []string{"dracon", "is", "not", "smithy"},
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly a non empty list string",
			param: v1.Parameter{
				Name:  "non-empty-list-str",
				Type:  v1.ParameterTypeListString,
				Value: []string{"dracon", "is", "not", "smithy"},
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an empty list string",
			param: v1.Parameter{
				Name:  "empty-list-str",
				Type:  v1.ParameterTypeListString,
				Value: make([]string, 0),
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an empty list string",
			param: v1.Parameter{
				Name:  "empty-list-str",
				Type:  v1.ParameterTypeListString,
				Value: make([]string, 0),
			},
			encoding: encodingYAML,
		},
		{
			testCase: "it should JSON marshal correctly an nil list string",
			param: v1.Parameter{
				Name:  "nil-list-str",
				Type:  v1.ParameterTypeListString,
				Value: nil,
			},
			encoding: encodingJSON,
		},
		{
			testCase: "it should YAML marshal correctly an nil list string",
			param: v1.Parameter{
				Name:  "nil-list-str",
				Type:  v1.ParameterTypeListString,
				Value: nil,
			},
			encoding: encodingYAML,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			var (
				bb    []byte
				err   error
				param v1.Parameter
			)

			switch tt.encoding {
			case encodingJSON:
				bb, err = json.Marshal(tt.param)
			case encodingYAML:
				bb, err = yaml.Marshal(tt.param)
			default:
				require.Failf(t, "unknown encoding %s", tt.encoding)
			}

			if tt.expectsMarshalErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			switch tt.encoding {
			case encodingJSON:
				err = json.Unmarshal(bb, &param)
			case encodingYAML:
				err = yaml.Unmarshal(bb, &param)
			default:
				require.Failf(t, "unknown encoding %s", tt.encoding)
			}

			if tt.expectsUnmarshalErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, param.Type, tt.param.Type)
			require.Equal(t, param.Name, tt.param.Name)
			validateStringParam(t, param, tt.param)
			validateListParam(t, param, tt.param)
			require.NoError(t, param.Validate())
		})
	}
}

func validateStringParam(t *testing.T, expectedParam, givenParam v1.Parameter) {
	t.Helper()

	if expectedParam.Type != v1.ParameterTypeString && expectedParam.Type != v1.ParameterTypeConstString {
		return
	}

	var (
		givenParamVal    = getStrVal(t, givenParam.Value)
		expectedParamVal = getStrVal(t, expectedParam.Value)
	)

	require.Equal(t, expectedParamVal, givenParamVal)
}

func validateListParam(t *testing.T, expectedParam, givenParam v1.Parameter) {
	t.Helper()

	if expectedParam.Type != v1.ParameterTypeListString {
		return
	}

	expectedVals, ok := expectedParam.Value.([]string)
	require.True(t, ok)

	var givenVals []string
	if givenParam.Value != nil {
		givenVals, ok = givenParam.Value.([]string)
		require.True(t, ok)
	}

	require.ElementsMatch(t, expectedVals, givenVals)
}

func getStrVal(t *testing.T, val any) string {
	if val == nil {
		return ""
	}

	switch reflect.TypeOf(val).Kind() {
	case reflect.String:
		return val.(string)
	case reflect.Ptr:
		vs, ok := val.(*string)
		require.True(t, ok)
		if vs != nil {
			return *vs
		}
	default:
		require.Failf(t, "unexpected value type: %s", reflect.ValueOf(val).Kind().String())
	}

	return ""
}
