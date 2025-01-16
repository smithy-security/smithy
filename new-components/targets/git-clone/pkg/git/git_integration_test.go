package git_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// TestGitCloneSuite sets up gitea and runs the git-clone container.
// It then verifies that cloning is successful.
type TestGitCloneSuite struct {
	suite.Suite

	testAbsPath       string
	dockerTestPool    *dockertest.Pool
	dockerTestNetwork *docker.Network
	dockerResources   []*dockertest.Resource
}

func TestTestGitCloneSuite(t *testing.T) {
	t.Skip("TODO: Re-enable when fixing https://linear.app/smithy/issue/OCU-482/make-sure-git-cloner-integration-test-works-on-ci")
	suite.Run(t, new(TestGitCloneSuite))
}

func (s *TestGitCloneSuite) SetupTest() {
	pool, err := dockertest.NewPool("")
	require.NoError(s.T(), err)

	s.dockerTestPool = pool

	var (
		ctx, cancel         = context.WithTimeout(context.Background(), 5*time.Minute)
		healthCheckerClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	)

	defer cancel()

	dockerNetwork, err := pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:   "test-network",
		Driver: "bridge",
	})
	require.NoError(s.T(), err)
	s.dockerTestNetwork = dockerNetwork

	absPath, err := filepath.Abs(".")
	require.NoError(s.T(), err)
	s.testAbsPath = absPath

	gitea, err := pool.RunWithOptions(
		&dockertest.RunOptions{
			Name:       "gitea",
			Platform:   "linux/amd64",
			Repository: "gitea/gitea",
			Tag:        "latest",
			WorkingDir: "/workspace",
			Env: []string{
				"USER_UID=1000",
				"USER_GID=1000",
				"GITEA__database__DB_TYPE=sqlite3",
				"GITEA__server__ROOT_URL=http://localhost:3000",
				"GITEA__security__INSTALL_LOCK=true",
				"GITEA__security__DISABLE_AUTHENTICATION=true",
			},
			ExposedPorts: []string{
				"3000/tcp",
			},
			PortBindings: map[docker.Port][]docker.PortBinding{
				"3000/tcp": {
					{HostIP: "0.0.0.0", HostPort: "3000"},
				},
			},
			Networks: []*dockertest.Network{
				{
					Network: dockerNetwork,
				},
			},
		}, func(config *docker.HostConfig) {
			config.Binds = []string{
				path.Join(absPath, "testdata/gitea/data:/data"),
			}
		})

	require.NoError(s.T(), err)
	require.NoError(s.T(), pool.Retry(func() error {
		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			"http://localhost:3000",
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := healthCheckerClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get health check: %w", err)
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}

		return nil
	}))

	ctxDirPath, err := filepath.Abs("../..")
	require.NoError(s.T(), err)

	seeder, err := pool.BuildAndRunWithBuildOptions(
		&dockertest.BuildOptions{
			ContextDir: ctxDirPath,
			Dockerfile: "dockerfiles/seeder/Dockerfile",
			Platform:   "linux/amd64",
		},
		&dockertest.RunOptions{
			Name: "seeder",
			Env: []string{
				"GIT_REPO_NAME=testrepo",
				"GITEA_ADMIN_PASSWORD=smithy1234",
				"GITEA_URL=http://gitea:3000",
				"GITEA_ADMIN_USER=gitcloner",
			},
			Networks: []*dockertest.Network{
				{
					Network: dockerNetwork,
				},
			},
		}, func(config *docker.HostConfig) {
			config.Binds = []string{
				path.Join(absPath, "testdata/gitea/data:/data"),
			}
		},
	)

	require.NoError(s.T(), err)

	gitCloneTarget, err := pool.BuildAndRunWithBuildOptions(
		&dockertest.BuildOptions{
			ContextDir: ctxDirPath,
			Dockerfile: "dockerfiles/git-clone/Dockerfile",
			Platform:   "linux/amd64",
		},
		&dockertest.RunOptions{
			Name: "target",
			Env: []string{
				"SMITHY_INSTANCE_ID=8d719c1c-c569-4078-87b3-4951bd4012ee",
				"SMITHY_LOG_LEVEL=debug",
				"SMITHY_BACKEND_STORE_TYPE=local",
				"GIT_CLONE_REPO_URL=http://gitea:3000/gitcloner/testrepo.git",
				"GIT_CLONE_REFERENCE=main",
			},
			Networks: []*dockertest.Network{
				{
					Network: dockerNetwork,
				},
			},
		}, func(config *docker.HostConfig) {
			config.Binds = []string{
				path.Join(absPath, "testdata/testrepo:/workspace"),
			}
		},
	)

	require.NoError(s.T(), err)

	require.NoError(s.T(), pool.Client.Logs(docker.LogsOptions{
		Context:      ctx,
		Container:    gitCloneTarget.Container.ID,
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
		Stdout:       true,
		Stderr:       true,
		Follow:       true,
	}))

	s.dockerResources = []*dockertest.Resource{
		seeder,
		gitCloneTarget,
		gitea,
	}
}

func (s *TestGitCloneSuite) TearDownTest() {
	for _, res := range s.dockerResources {
		_ = s.dockerTestPool.Purge(res)
	}
	_ = s.dockerTestPool.RemoveNetwork(&dockertest.Network{Network: s.dockerTestNetwork})
	_ = os.RemoveAll(path.Join(s.testAbsPath, "testdata"))
}

func (s *TestGitCloneSuite) TestGitClone() {
	s.T().Run("git-clone target should have successfully cloned testrepo", func(t *testing.T) {
		clonePath := path.Join(s.testAbsPath, "testdata/testrepo")

		testRepoDir, err := os.Stat(clonePath)
		require.NoError(s.T(), err)
		require.True(s.T(), testRepoDir.IsDir())
	})
}
