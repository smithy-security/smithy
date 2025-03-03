package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path"
	"strings"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

func TestBuilder(t *testing.T) {
	testCtx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	ctrl := gomock.NewController(t)
	dockerBuilderMock := NewMockdockerBuilder(ctrl)

	bb := bytes.NewBuffer([]byte{})
	bb.WriteString("this is fine\n")
	require.NoError(
		t,
		json.NewEncoder(bb).Encode(buildErrorLine{
			Error: "build has failed",
			ErrorDetail: buildErrorDetail{
				Message: "there is some file missing",
			},
		}),
	)
	buildReadCloser := io.NopCloser(bb)
	tarReadCloser := io.NopCloser(strings.NewReader("bla"))

	componentDirectory := "testdata/scanners/gosec"

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
	require.Error(t, err)
	require.Contains(t, err.Error(), "there is some file missing")
}
