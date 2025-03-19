package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"path"
	"strings"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	dockerimagetypes "github.com/docker/docker/api/types/image"
	dockerregistrytypes "github.com/docker/docker/api/types/registry"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

func TestBuilder(t *testing.T) {
	testCtx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	ctrl := gomock.NewController(t)
	dockerBuilderMock := NewMockdockerBuilder(ctrl)

	t.Run("docker builder returns an error", func(t *testing.T) {
		bb := bytes.NewBuffer([]byte{})
		bb.WriteString("this is fine\n")
		require.NoError(
			t,
			json.NewEncoder(bb).Encode(errorLine{
				Error: "build has failed",
				ErrorDetail: errorDetail{
					Message: "there is some file missing",
				},
			}),
		)
		buildReadCloser := io.NopCloser(bb)
		tarReadCloser := io.NopCloser(strings.NewReader("bla"))

		componentDirectory := "testdata/scanners/gosec"
		sdkVersion := "1.0.0"

		gomock.InOrder(
			dockerBuilderMock.
				EXPECT().
				ServerVersion(testCtx).
				Return(
					dockertypes.Version{
						Os:   "minix",
						Arch: "x68",
					},
					nil,
				),

			dockerBuilderMock.
				EXPECT().
				ImageBuild(
					testCtx,
					tarReadCloser,
					dockertypes.ImageBuildOptions{
						Tags:       []string{path.Join(images.DefaultRegistry, images.DefaultNamespace, "testdata/scanners/gosec:latest")},
						PullParent: true,
						Platform:   "minix/x68",
						BuildArgs: map[string]*string{
							"COMPONENT_PATH": &componentDirectory,
							"SDK_VERSION":    &sdkVersion,
						},
						Labels:     images.DefaultLabels,
						Dockerfile: "testdata/Dockerfile",
					},
				).
				Return(
					dockertypes.ImageBuildResponse{
						Body:   buildReadCloser,
						OSType: "minix/x68",
					},
					nil,
				),
		)

		builder, err := NewBuilder(
			testCtx,
			dockerBuilderMock,
			"components/scanners/test/component.yaml",
			false,
			WithBaseDockerfilePath("testdata/Dockerfile"),
			WithSDKVersion("1.0.0"),
		)
		require.NoError(t, err)

		builder.prepareTar = func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error) {
			require.Equal(t, "testdata/Dockerfile", baseDockerfilePath)
			require.Equal(t, "testdata/scanners/gosec", path)
			require.Empty(t, extraPaths)
			return tarReadCloser, nil
		}

		componentRepo, _, err := images.ParseComponentRepository(
			"testdata/scanners/gosec/component.yaml",
			"testdata/scanners/gosec",
		)
		require.NoError(t, err)

		_, err = builder.Build(testCtx, componentRepo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "there is some file missing")
	})

	t.Run("docker builder returns success", func(t *testing.T) {
		bb := bytes.NewBuffer([]byte{})
		bb.WriteString("this is fine\n")
		bb.WriteString("build finished without issues\n")
		buildReadCloser := io.NopCloser(bb)
		tarReadCloser := io.NopCloser(strings.NewReader("bla"))

		componentDirectory := "testdata/scanners/gosec"
		sdkVersion := "unset"

		gomock.InOrder(
			dockerBuilderMock.
				EXPECT().
				ServerVersion(testCtx).
				Return(
					dockertypes.Version{
						Os:   "minix",
						Arch: "x68",
					},
					nil,
				),

			dockerBuilderMock.
				EXPECT().
				ImageBuild(
					testCtx,
					tarReadCloser,
					dockertypes.ImageBuildOptions{
						Tags:       []string{path.Join(images.DefaultRegistry, images.DefaultNamespace, "testdata/scanners/gosec:latest")},
						PullParent: true,
						Platform:   "minix/x68",
						BuildArgs: map[string]*string{
							"COMPONENT_PATH": &componentDirectory,
							"SDK_VERSION":    &sdkVersion,
						},
						Labels:     images.DefaultLabels,
						Dockerfile: "testdata/Dockerfile",
					},
				).
				Return(
					dockertypes.ImageBuildResponse{
						Body:   buildReadCloser,
						OSType: "minix/x68",
					},
					nil,
				),
		)

		builder, err := NewBuilder(
			testCtx,
			dockerBuilderMock,
			"components/scanners/test/component.yaml",
			false,
			WithBaseDockerfilePath("testdata/Dockerfile"),
		)
		require.NoError(t, err)

		builder.prepareTar = func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error) {
			require.Equal(t, "testdata/Dockerfile", baseDockerfilePath)
			require.Equal(t, "testdata/scanners/gosec", path)
			require.Empty(t, extraPaths)
			return tarReadCloser, nil
		}

		componentRepo, _, err := images.ParseComponentRepository(
			"testdata/scanners/gosec/component.yaml",
			"testdata/scanners/gosec",
		)
		require.NoError(t, err)

		_, err = builder.Build(testCtx, componentRepo)
		require.NoError(t, err)
	})

	t.Run("docker build and push", func(t *testing.T) {
		bb := bytes.NewBuffer([]byte{})
		bb.WriteString("{\"stream\":\"BUILDING something\"}\n")
		bb.WriteString("{\"stream\":\"\n\"}\n")
		bb.WriteString("build finished without issues\n")
		buildReadCloser := io.NopCloser(bb)
		tarReadCloser := io.NopCloser(strings.NewReader("bla"))
		pushReadCloser := io.NopCloser(strings.NewReader("{\"status\":\"Layer already exists\",\"progressDetail\":{},\"id\":\"a80545a98dcd\"}"))

		componentDirectory := "testdata/scanners/gosec"
		sdkVersion := "unset"

		authConfigBytes, err := json.Marshal(dockerregistrytypes.AuthConfig{
			Username: "user",
			Password: "pass",
		})
		require.NoError(t, err)
		authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

		gomock.InOrder(
			dockerBuilderMock.
				EXPECT().
				ServerVersion(testCtx).
				Return(
					dockertypes.Version{
						Os:   "minix",
						Arch: "x68",
					},
					nil,
				),

			dockerBuilderMock.
				EXPECT().
				ImageBuild(
					testCtx,
					tarReadCloser,
					dockertypes.ImageBuildOptions{
						Tags:       []string{path.Join(images.DefaultRegistry, images.DefaultNamespace, "testdata/scanners/gosec:latest")},
						PullParent: true,
						Platform:   "minix/x68",
						BuildArgs: map[string]*string{
							"COMPONENT_PATH": &componentDirectory,
							"SDK_VERSION":    &sdkVersion,
						},
						Labels:     images.DefaultLabels,
						Dockerfile: "testdata/Dockerfile",
					},
				).
				Return(
					dockertypes.ImageBuildResponse{
						Body:   buildReadCloser,
						OSType: "minix/x68",
					},
					nil,
				),

			dockerBuilderMock.
				EXPECT().
				ImagePush(
					testCtx,
					"ghcr.io/smithy-security/smithy/testdata/scanners/gosec:latest",
					dockerimagetypes.PushOptions{
						RegistryAuth: authConfigEncoded,
					},
				).
				Return(
					pushReadCloser,
					nil,
				),
		)

		builder, err := NewBuilder(
			testCtx,
			dockerBuilderMock,
			"components/scanners/test/component.yaml",
			false,
			WithBaseDockerfilePath("testdata/Dockerfile"),
			WithUsernamePassword("user", "pass"),
			PushImages(),
		)
		require.NoError(t, err)

		builder.prepareTar = func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error) {
			require.Equal(t, "testdata/Dockerfile", baseDockerfilePath)
			require.Equal(t, "testdata/scanners/gosec", path)
			require.Empty(t, extraPaths)
			return tarReadCloser, nil
		}

		componentRepo, _, err := images.ParseComponentRepository(
			"testdata/scanners/gosec/component.yaml",
			"testdata/scanners/gosec",
		)
		require.NoError(t, err)

		_, err = builder.Build(testCtx, componentRepo)
		require.NoError(t, err)
	})
}
