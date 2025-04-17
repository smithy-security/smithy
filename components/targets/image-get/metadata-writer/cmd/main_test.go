package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteTargetMetadata(t *testing.T) {
	tests := []struct {
		name           string
		conf           Conf
		expectedError  bool
		expectedOutput string
	}{
		{
			name: "Valid image with full URL and version tag",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/image:1.0.0",
			},
			expectedError:  false,
			expectedOutput: `{"targetType":"TARGET_TYPE_CONTAINER_IMAGE","ociPackageMetadata":{"packageUrl":"pkg:docker/repo.example.com/project%2Fimage@1.0.0","tag":"1.0.0"}}`,
		},
		{
			name: "Valid image with no tag (latest assumed)",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/image",
			},
			expectedOutput: `{"targetType":"TARGET_TYPE_CONTAINER_IMAGE","ociPackageMetadata":{"packageUrl":"pkg:docker/repo.example.com/project%2Fimage@latest","tag":"latest"}}`,
		},
		{
			name: "Valid image with latest tag",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/image:latest",
			},
			expectedError:  false,
			expectedOutput: `{"targetType":"TARGET_TYPE_CONTAINER_IMAGE","ociPackageMetadata":{"packageUrl":"pkg:docker/repo.example.com/project%2Fimage@latest","tag":"latest"}}`,
		},
		{
			name: "Valid image with SHA tag",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/ubuntu@sha256:98706f0f213dbd440021993a82d2f70451a73698315370ae8615cc468ac06624",
			},
			expectedError:  false,
			expectedOutput: `{"targetType":"TARGET_TYPE_CONTAINER_IMAGE","ociPackageMetadata":{"packageUrl":"pkg:docker/repo.example.com/project%2Fubuntu?digest=sha256%3A98706f0f213dbd440021993a82d2f70451a73698315370ae8615cc468ac06624"}}`,
		},
		{
			name: "Valid image with SHA AND tag",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/ubuntu:18.04@sha256:98706f0f213dbd440021993a82d2f70451a73698315370ae8615cc468ac06624",
			},
			expectedError:  false,
			expectedOutput: `{"targetType":"TARGET_TYPE_CONTAINER_IMAGE","ociPackageMetadata":{"packageUrl":"pkg:docker/repo.example.com/project%2Fubuntu?digest=sha256%3A98706f0f213dbd440021993a82d2f70451a73698315370ae8615cc468ac06624"}}`,
		},
		{
			name: "Invalid image with empty string",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "",
			},
			expectedError: true,
		},
		{
			name: "Invalid image with malformed tag",
			conf: Conf{
				TargetMetadataPath: "",
				Image:              "repo.example.com/project/image:tag:extra",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file for testing
			tempFile, err := os.CreateTemp("", "target.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tempFile.Name())

			// Update the conf to use the temp file path
			tt.conf.TargetMetadataPath = tempFile.Name()

			err = WriteTargetMetadata(tt.conf)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Read the file and verify its contents
				data, readErr := os.ReadFile(tempFile.Name())
				assert.NoError(t, readErr)
				assert.JSONEq(t, tt.expectedOutput, string(data))
			}
		})
	}
}
