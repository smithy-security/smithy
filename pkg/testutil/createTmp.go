// Package testutil contains helper functions and subpackages to make testing the project easier
package testutil

import (
	"os"

	"github.com/go-errors/errors"
)

// CreateFile creates a temporary file with the contents passed in the relevant param
// deleting the file is the responsibility of the caller
func CreateFile(filename, content string) (*os.File, error) {
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return nil, errors.Errorf("could not setup tests for pkg, could not create temporary files")
	}
	if err := os.WriteFile(file.Name(), []byte(content), os.ModeAppend); err != nil {
		return nil, errors.Errorf("could not setup tests for pkg, could not write temporary file")
	}
	return file, nil
}
