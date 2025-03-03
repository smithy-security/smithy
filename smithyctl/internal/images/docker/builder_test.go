package docker

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

func TestBuilder(t *testing.T) {
	testCtx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	ctrl := gomock.NewController(t)
	dockerBuilerMock := NewMockdockerBuilder(ctrl)

	builder, err := NewBuilder(dockerBuilerMock)
	require.NoError(t, err)

	imageRepo, err := name.NewRepository("new-components/scanners/gosec")
	require.NoError(t, err)

	componentRepo, err := images.NewComponentRepository(imageRepo)
	require.NoError(t, err)

	builder.componentFolder = "./testdata"
	fp, err := os.OpenFile("./testdata/scanners/gosec.tar", os.O_RDONLY, 0666)
	require.NoError(t, err)

	bb := bytes.NewBuffer([]byte{})
	_, err = bb.ReadFrom(fp)
	require.NoError(t, err)

	dockerBuilerMock.EXPECT().ImageBuild(testCtx, bb, dockertypes.ImageBuildOptions{
		Tags:       []string{"ew-components/scanners/gosec:latest"},
		PullParent: true,
		Labels: map[string]string{
			"org.opencontainers.image.source": "https://github.com/smithy-security/smithy",
		},
		Dockerfile: "testdata/Dockerfile",
	})
	require.NoError(t, builder.Build(testCtx, componentRepo))
}
