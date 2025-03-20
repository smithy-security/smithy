package target

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	dockerclient "github.com/docker/docker/client"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/config"
	dockercomponent "github.com/smithy-security/smithy/new-components/targets/image-get/internal/docker"
)

var (
	imageRef     = "hello-world:latest"
	registryAddr = "localhost:5000"
	makeLoader   = func(envs map[string]string) env.Loader {
		return func(key string) string {
			return envs[key]
		}
	}
)

type (
	RegistryTestSuite struct {
		suite.Suite

		pool             *dockertest.Pool
		registryResource *dockertest.Resource
	}
)

func TestRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(RegistryTestSuite))
}

func (suite *RegistryTestSuite) SetupTest(withAuth bool) string {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
		err         error
	)

	defer cancel()
	registryEnv := []string{}
	if withAuth {
		slog.Info("withAuth is true, setting up registry with authentication requirements")
		registryEnv = []string{
			"REGISTRY_AUTH_SILLY_REALM='foobar.com'",
			"REGISTRY_AUTH_SILLY_SERVICE='foobar.com'",
		}
	}

	suite.pool, err = dockertest.NewPool("")
	require.NoError(suite.T(), err)

	suite.registryResource, err = suite.pool.RunWithOptions(&dockertest.RunOptions{
		Name:       "registry",
		Platform:   "linux/amd64",
		Repository: "registry",
		Tag:        "2",
		Env:        registryEnv,
	}, func(config *docker.HostConfig) {})
	require.NoError(suite.T(), err)

	require.NoError(suite.T(), suite.pool.Retry(func() error {
		var (
			pingCtx, pingCancel = context.WithTimeout(ctx, 1*time.Second)
			port                = suite.registryResource.GetHostPort("5000/tcp")
		)
		defer pingCancel()

		req, err := http.NewRequestWithContext(
			pingCtx,
			http.MethodGet,
			fmt.Sprintf("http://%s", port),
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to create registry request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute registry request: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		return nil
	}))

	// pull and push hello-world image
	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(suite.T(), err)

	_, err = dockerClient.ImagePull(context.Background(), imageRef, image.PullOptions{}) // pull from dockerhub
	require.NoError(suite.T(), err)

	newTag := fmt.Sprintf("%s/%s", registryAddr, imageRef)
	err = dockerClient.ImageTag(context.Background(), imageRef, newTag)
	require.NoError(suite.T(), err)

	imagePushOpts := image.PushOptions{}
	if withAuth {
		slog.Info("`withAuth` is true, setting up image pushing with authentication")
		authConfig := registry.AuthConfig{
			Username: "foobar",
			Password: "bar foo",
		}
		encodedJSON, err := json.Marshal(authConfig)
		require.NoError(suite.T(), err)

		imagePushOpts = image.PushOptions{RegistryAuth: base64.URLEncoding.EncodeToString(encodedJSON)}
	}
	_, err = dockerClient.ImagePush(ctx, newTag, imagePushOpts) // push to local
	require.NoError(suite.T(), err)

	return suite.T().TempDir()
}

func (suite *RegistryTestSuite) TearDownTest() {
	if suite.pool != nil && suite.registryResource != nil {
		_ = suite.pool.Purge(suite.registryResource)
	}
}

func (suite *RegistryTestSuite) TestPrepareWithPublicImages() {
	t := suite.T()
	defer suite.TearDownTest()
	workdir := suite.SetupTest(false)

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	c, err := config.New(makeLoader(
		map[string]string{
			"IMAGE_REF":  "localhost:5000/" + imageRef,
			"USERNAME":   "",
			"TOKEN":      "",
			"TARGET_DIR": workdir,
		},
	))
	require.NoError(t, err)
	dockerResolver, err := dockercomponent.NewResolver(dockerClient, c)
	require.NoError(t, err)
	target, err := New(c, WithResolver(dockerResolver))
	require.NoError(t, err)
	err = target.Prepare(context.Background())
	require.NoError(t, err)

	require.FileExists(t, path.Join(workdir, "image.tar.gz"))
}

func (suite *RegistryTestSuite) TestPrepareWithAuthImages() {
	t := suite.T()
	defer suite.TearDownTest()
	workdir := suite.SetupTest(true)

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	c, err := config.New(makeLoader(
		map[string]string{
			"IMAGE_REF":  "localhost:5000/" + imageRef,
			"USERNAME":   "blah",
			"TARGET_DIR": workdir,
		},
	))
	require.NoError(t, err)
	dockerResolver, err := dockercomponent.NewResolver(dockerClient, c)
	require.NoError(t, err)
	target, err := New(c, WithResolver(dockerResolver))
	require.NoError(t, err)
	err = target.Prepare(context.Background())
	require.NoError(t, err)

	require.FileExists(t, path.Join(workdir, "image.tar.gz"))
}
