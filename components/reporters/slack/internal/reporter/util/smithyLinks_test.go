package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

func TestMakeFindingLink(t *testing.T) {
	tests := []struct {
		host      string
		findingID uint64
		expected  string
	}{
		{"example.com", 12345, "https://example.com/issues/12345"},
		{"test.com", 0, "https://test.com/issues/0"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := MakeFindingLink(tt.host, tt.findingID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeRunLink(t *testing.T) {
	tests := []struct {
		host       string
		instanceID string
		expected   string
	}{
		{"example.com", "run123", "https://example.com/runs/run123"},
		{"test.com", "", "https://test.com/runs"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := MakeRunLink(tt.host, tt.instanceID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeRepositoryLink(t *testing.T) {
	tests := []struct {
		name     string
		data     *ocsffindinginfo.DataSource
		expected string
		hasError bool
	}{
		{
			name: "Valid GitHub link",
			data: &ocsffindinginfo.DataSource{
				SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
					RepositoryUrl: "https://github.com/example/repo",
					Reference:     "main",
				},
				LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
					FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
						StartLine: 10,
						EndLine:   20,
					},
				},
				Uri: &ocsffindinginfo.DataSource_URI{
					Path: "file.go",
				},
			},
			expected: "https://github.com/example/repo/blob/main/file.go#L10-L20",
			hasError: false,
		},
		{
			name: "Non-GitHub link",
			data: &ocsffindinginfo.DataSource{
				SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
					RepositoryUrl: "https://gitlab.com/example/repo",
				},
			},
			expected: "https://gitlab.com/example/repo",
			hasError: false,
		},
		{
			name: "Invalid repository URL",
			data: &ocsffindinginfo.DataSource{
				SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
					RepositoryUrl: "://invalid-url",
				},
			},
			expected: "",
			hasError: true,
		},
		{
			name: "Malformed end line",
			data: &ocsffindinginfo.DataSource{
				SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
					RepositoryUrl: "https://github.com/example/repo",
					Reference:     "main",
				},
				LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
					FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
						StartLine: 5,
						EndLine:   0,
					},
				},
				Uri: &ocsffindinginfo.DataSource_URI{
					Path: "file.go",
				},
			},
			expected: "https://github.com/example/repo/blob/main/file.go#L5-L5",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MakeRepositoryLink(tt.data)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
