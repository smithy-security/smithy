package manifests

import (
	"context"

	"github.com/smithy-security/smithy/pkg/files"
)

var _ files.Loader = fakeLoader{}

// fakeLoader is a struct that implements the `files.Loader` interface and can
// be used in tests as a mock object
type fakeLoader struct {
	path     string
	mockLoad func() ([]byte, error)
}

// NewFakeLoader returns an initialised FakeLoader
func NewFakeLoader(mockPath string, mockLoad func() ([]byte, error)) files.Loader {
	return fakeLoader{
		path:     mockPath,
		mockLoad: mockLoad,
	}
}

// Load returns a byte slice of a mock object
func (f fakeLoader) Load(_ context.Context) ([]byte, error) {
	return f.mockLoad()
}

// Path returns the mock file path
func (f fakeLoader) Path() string {
	return f.path
}
