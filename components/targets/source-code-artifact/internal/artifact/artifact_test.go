package artifact_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
)

func TestGetSourceType(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected artifact.SourceType
		wantErr  bool
	}{
		{
			name:     "S3 URL",
			source:   "s3://my-bucket/archive.tar.gz",
			expected: artifact.SourceTypeS3,
			wantErr:  false,
		},
		{
			name:     "S3 URL with path",
			source:   "s3://bucket/path/to/file.zip",
			expected: artifact.SourceTypeS3,
			wantErr:  false,
		},
		{
			name:     "GCS URL",
			source:   "gs://my-bucket/archive.tar",
			expected: artifact.SourceTypeGCS,
			wantErr:  false,
		},
		{
			name:     "GCS URL with path",
			source:   "gs://bucket/deep/path/file.tar.gz",
			expected: artifact.SourceTypeGCS,
			wantErr:  false,
		},
		{
			name:     "HTTP URL",
			source:   "https://github.com/example/repo/archive/main.zip",
			expected: artifact.SourceTypeRemote,
			wantErr:  false,
		},
		{
			name:     "HTTPS URL",
			source:   "https://example.com/file.tar.gz",
			expected: artifact.SourceTypeRemote,
			wantErr:  false,
		},
		{
			name:     "HTTP URL",
			source:   "http://example.com/archive.tar",
			expected: artifact.SourceTypeRemote,
			wantErr:  false,
		},
		{
			name:     "FTP URL",
			source:   "ftp://example.com/file.zip",
			expected: artifact.SourceTypeUnsupported,
			wantErr:  true,
		},
		{
			name:     "File path",
			source:   "/local/path/to/file.tar.gz",
			expected: artifact.SourceTypeUnsupported,
			wantErr:  true,
		},
		{
			name:     "Empty string",
			source:   "",
			expected: artifact.SourceTypeUnsupported,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := artifact.GetSourceType(tt.source)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetFileType(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		expected artifact.FileType
		wantErr  bool
	}{
		{
			name:     "ZIP file",
			fileName: "archive.zip",
			expected: artifact.FileTypeZip,
			wantErr:  false,
		},
		{
			name:     "ZIP file with path",
			fileName: "/path/to/archive.zip",
			expected: artifact.FileTypeZip,
			wantErr:  false,
		},
		{
			name:     "TAR file",
			fileName: "archive.tar",
			expected: artifact.FileTypeTar,
			wantErr:  false,
		},
		{
			name:     "TAR file with path",
			fileName: "/path/to/archive.tar",
			expected: artifact.FileTypeTar,
			wantErr:  false,
		},
		{
			name:     "TAR.GZ file",
			fileName: "archive.tar.gz",
			expected: artifact.FileTypeTarGz,
			wantErr:  false,
		},
		{
			name:     "TAR.GZ file with path",
			fileName: "/path/to/archive.tar.gz",
			expected: artifact.FileTypeTarGz,
			wantErr:  false,
		},
		{
			name:     "Full URL with ZIP",
			fileName: "https://github.com/example/repo/archive/refs/heads/main.zip",
			expected: artifact.FileTypeZip,
			wantErr:  false,
		},
		{
			name:     "S3 URL with TAR.GZ",
			fileName: "s3://bucket/path/archive.tar.gz",
			expected: artifact.FileTypeTarGz,
			wantErr:  false,
		},
		{
			name:     "Empty string",
			fileName: "",
			expected: artifact.FileTypeUnsupported,
			wantErr:  false,
		},
		{
			name:     "Just tar.gz extension",
			fileName: ".tar.gz",
			expected: artifact.FileTypeTarGz,
			wantErr:  false,
		},
		{
			name:     "Not archived",
			fileName: "SBOM.json",
			expected: artifact.FileTypeUnarchived,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := artifact.GetFileType(tt.fileName)

			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, tt.expected, result)
				require.Contains(t, err.Error(), "unsupported file type")
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestStringMethods(t *testing.T) {
	t.Run("SourceType String method", func(t *testing.T) {
		require.Equal(t, "s3", artifact.SourceTypeS3.String())
		require.Equal(t, "gcs", artifact.SourceTypeGCS.String())
		require.Equal(t, "remote", artifact.SourceTypeRemote.String())
		require.Equal(t, "unsupported", artifact.SourceTypeUnsupported.String())
	})

	t.Run("FileType String method", func(t *testing.T) {
		require.Equal(t, "zip", artifact.FileTypeZip.String())
		require.Equal(t, "tar", artifact.FileTypeTar.String())
		require.Equal(t, "tar.gz", artifact.FileTypeTarGz.String())
		require.Equal(t, "unsupported", artifact.FileTypeUnsupported.String())
	})
}
