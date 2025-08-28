package utils

import "iter"

// CollectSlices collects a sequence of slices into one slice
func CollectSlices[I any](batches [][]I) iter.Seq[I] {
	return func(yield func(I) bool) {
		for _, batch := range batches {
			for _, item := range batch {
				if !yield(item) {
					return
				}
			}
		}
	}
}

// MapSlice returns a modified slie of elements based on a converter function
func MapSlice[I any, O any](s iter.Seq[I], f func(I) O) iter.Seq[O] {
	return func(yield func(O) bool) {
		for i := range s {
			if !yield(f(i)) {
				return
			}
		}
	}
}
