package files

import (
	"context"

	"os"
	"path"
	"path/filepath"

	"github.com/go-errors/errors"
)

var _ Loader = (*localFileLoader)(nil)

type localFileLoader struct {
	path string
}

func newLocalFileLoader(configurationDir, fileOrDir, targetFile string) (*localFileLoader, error) {
	if !filepath.IsAbs(fileOrDir) {
		fileOrDir = path.Clean(filepath.Join(configurationDir, fileOrDir))
	}

	info, err := os.Stat(fileOrDir)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		fileOrDir = path.Join(fileOrDir, targetFile)
	} else if path.Base(fileOrDir) != targetFile {
		return nil, errors.Errorf("path %s should be pointing to a %s", fileOrDir, targetFile)
	}

	return &localFileLoader{path: fileOrDir}, nil
}

// Path returns the path in the local file system
func (lfl *localFileLoader) Path() string {
	return lfl.path
}

// Load reads a file from the local file system
func (lfl *localFileLoader) Load(_ context.Context) ([]byte, error) {
	return os.ReadFile(lfl.path)
}
