package tar

import (
	"context"
	"os"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/common"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

// Untar is an extractor for tar archives
type Untar struct{}

// NewExtractor returns a new tar extractor.
func NewExtractor() Untar {
	return Untar{}
}

// ExtractArtifact plainly uses the Untar helper.
func (Untar) ExtractArtifact(ctx context.Context, sourcePath, destPath string) error {
	tmpArchive, err := os.OpenFile(sourcePath, os.O_RDONLY, 0600)
	if err != nil {
		return errors.Errorf("could not open temporary archive file for extracting: %w", err)
	}
	defer reader.CloseReader(ctx, tmpArchive)

	return common.Untar(ctx, tmpArchive, destPath)
}
