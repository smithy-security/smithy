package v1_test

import (
	"reflect"
	"slices"
	"testing"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

func ptr[T any](v T) *T {
	return &v
}

func TestParameter(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		testCase            string
		param               v1.Parameter
		expectsMarshalErr   bool
		expectsUnmarshalErr bool
	}{
		{
			testCase: "it should marshal correctly a non empty pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: ptr("smithy"),
			},
		},
		{
			testCase: "it should marshal correctly an empty pointer to a string",
			param: v1.Parameter{
				Name:  "empty-ptr-str",
				Type:  v1.ParameterTypeString,
				Value: "",
			},
		},
		{
			testCase: "it should marshal correctly a non empty string",
			param: v1.Parameter{
				Name:  "non-empty-str",
				Type:  v1.ParameterTypeString,
				Value: "smithy",
			},
		},
		{
			testCase: "it should marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-str",
				Type:  v1.ParameterTypeString,
				Value: ptr(""),
			},
		},
		{
			testCase: "it should marshal correctly an nil string",
			param: v1.Parameter{
				Name: "nil-str",
				Type: v1.ParameterTypeString,
			},
		},
		{
			testCase: "it should marshal correctly a non empty const pointer to a string",
			param: v1.Parameter{
				Name:  "non-empty-const-ptr-str",
				Type:  v1.ParameterTypeConststring,
				Value: ptr("{{.Helm.template.value}}"),
			},
		},
		{
			testCase: "it should marshal correctly an empty const pointer to a string",
			param: v1.Parameter{
				Name:  "empty-const-ptr-str",
				Type:  v1.ParameterTypeConststring,
				Value: ptr(""),
			},
		},
		{
			testCase: "it should marshal correctly a non empty const string",
			param: v1.Parameter{
				Name:  "non-empty-const-str",
				Type:  v1.ParameterTypeConststring,
				Value: "{{.Helm.template.value}}",
			},
		},
		{
			testCase: "it should marshal correctly an empty string",
			param: v1.Parameter{
				Name:  "empty-const-str",
				Type:  v1.ParameterTypeConststring,
				Value: "",
			},
		},
		{
			testCase: "it should marshal correctly an nil const string",
			param: v1.Parameter{
				Name: "nil-const-str",
				Type: v1.ParameterTypeConststring,
			},
		},
		{
			testCase: "it should marshal correctly a non empty list string",
			param: v1.Parameter{
				Name:  "non-empty-list-str",
				Type:  v1.ParameterTypeListstring,
				Value: []string{"dracon", "is", "not", "smithy"},
			},
		},
		{
			testCase: "it should marshal correctly an empty list string",
			param: v1.Parameter{
				Name:  "empty-list-str",
				Type:  v1.ParameterTypeListstring,
				Value: make([]string, 0),
			},
		},
		{
			testCase: "it should marshal correctly an nil list string",
			param: v1.Parameter{
				Name: "nil-list-str",
				Type: v1.ParameterTypeListstring,
			},
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			bb, err := tt.param.MarshalJSON()
			if tt.expectsMarshalErr && err == nil {
				t.Fatalf("expected marshal error but got nil")
			} else if !tt.expectsMarshalErr && err != nil {
				t.Fatalf("expected no marshal error but got %v", err)
			}

			var param v1.Parameter
			err = param.UnmarshalJSON(bb)
			if tt.expectsUnmarshalErr && err == nil {
				t.Fatalf("expected unmarshal error but got nil")
			} else if !tt.expectsUnmarshalErr && err != nil {
				t.Fatalf("expected no unmarshal error but got %v", err)
			}

			if tt.param.Type != v1.ParameterTypeListstring {
				switch {
				case tt.param.Type != param.Type:
					t.Fatalf("expected param type %v but got %v", tt.param.Type, param.Type)
				case tt.param.Name != param.Name:
					t.Fatalf("expected param name %v but got %v", tt.param.Name, param.Name)
				default:
					var expectedVal string

					if tt.param.Value != nil {
						if reflect.TypeOf(tt.param.Value).Kind() == reflect.Ptr {
							expectedVal = *tt.param.Value.(*string)
						} else {
							expectedVal = tt.param.Value.(string)
						}
					}

					if param.Value != nil && expectedVal != param.Value.(string) {
						t.Fatalf("expected param value %v but got %v", expectedVal, param.Value)
					}
				}
				// In case of lists, we need to check element by element.
			} else if tt.param.Type == v1.ParameterTypeListstring && tt.param.Value != nil {
				for _, str := range param.Value.([]string) {
					if !slices.Contains(tt.param.Value.([]string), str) {
						t.Fatalf("expected list element '%s' to be found in slice '%v'", str, tt.param.Value)
					}
				}
			}
		})
	}
}
