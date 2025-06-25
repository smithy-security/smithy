package target_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/target"
)

func TestGetExtractor(t *testing.T) {
	for _, tt := range []struct {
		name        string
		fileName    string
		expFileType artifact.FileType
		expError    bool
	}{
		{
			name:        "file type not supported",
			fileName:    "not_supported",
			expFileType: artifact.FileTypeUnsupported,
			expError:    true,
		},
		{
			name:        "remote type",
			fileName:    "https://github.com/0c34/govwa/archive/refs/heads/master.zip",
			expFileType: artifact.FileTypeZip,
		},
		{
			name:        "tar type",
			fileName:    "gs://my-bucket/my-archive.tar",
			expFileType: artifact.FileTypeTar,
		},
		{
			name:        "tar gz type",
			fileName:    "s3://my-bucket/my-archive.tar.gz",
			expFileType: artifact.FileTypeTarGz,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extractor, fileType, err := target.GetExtractor(tt.fileName)
			if tt.expError {
				require.Error(t, err)
				require.Nil(t, extractor)
				assert.Equal(t, artifact.FileTypeUnsupported, fileType)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, extractor)
			assert.Equal(t, tt.expFileType, fileType)
		})
	}
}
