package utils

import "reflect"

// IsNil checks if a value is actually nil even if it's an instance of an
// interface
func IsNil(v any) bool {
	return v == nil ||
		((reflect.ValueOf(v).Kind() == reflect.Ptr || reflect.ValueOf(v).Kind() == reflect.Func) &&
			reflect.ValueOf(v).IsNil())
}
