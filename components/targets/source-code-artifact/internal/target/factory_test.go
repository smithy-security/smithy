package target_test

import (
	"testing"

	"github.com/smithy-security/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/target"
)

func TestGetExtractor(t *testing.T) {
	for _, tt := range []struct {
		name     string
		fileType artifact.FileType
		err      error
	}{
		{
			name:     "file type not supported",
			fileType: artifact.FileTypeUnsupported,
			err:      target.ErrUnsupportedFileType,
		},
		{
			name:     "remote type",
			fileType: artifact.FileTypeZip,
		},
		{
			name:     "tar type",
			fileType: artifact.FileTypeTar,
		},
		{
			name:     "tar gz type",
			fileType: artifact.FileTypeTarGz,
		},
		{
			name:     "any type",
			fileType: artifact.FileTypeUnarchived,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extractor, fileType, err := target.GetExtractor(tt.fileType)
			require.ErrorIs(t, err, tt.err)
			assert.Equal(t, tt.fileType, fileType)
			assert.True(t, (tt.err == nil && !utils.IsNil(extractor)) || (tt.err != nil && utils.IsNil(extractor)))
		})
	}
}
