package utils

// Ptr returns a pointer to the passed value.
func Ptr[T any](v T) *T {
	return &v
}
