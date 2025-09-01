package persister

import (
	"context"
	"io"
	"os"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

// SimpleFSPersister writes a byte stream into a file in the filesystem
type SimpleFSPersister struct{}

// New returns a new simple filesystem persister.
func New() SimpleFSPersister {
	return SimpleFSPersister{}
}

// Persist copies the bytes from the io.Reader directly into the desired archive location.
func (SimpleFSPersister) Persist(ctx context.Context, dest string, rc io.Reader) error {
	tmpArchive, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Errorf("could not create temporary archive file: %w", err)
	}

	defer reader.CloseReader(ctx, tmpArchive)
	return reader.SafeCopy(ctx, tmpArchive, rc)
}
