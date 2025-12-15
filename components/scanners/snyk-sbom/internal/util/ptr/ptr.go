package ptr

// Ptr returns the pointer to the passed value.
func Ptr[T any](v T) *T {
	return &v
}
