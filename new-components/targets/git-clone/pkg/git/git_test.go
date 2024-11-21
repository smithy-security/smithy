package git_test

import (
	"testing"

	"github.com/smithy-security/pkg/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/targets/git-clone/pkg/git"
)

func TestNewConf(t *testing.T) {
	const (
		clonePath      = "/workspace"
		repoURL        = "https://github.com/andream16/go-opentracing-example"
		reference      = "main"
		accessToken    = "superSecureToken"
		accessUsername = "andrea@smithy.security"
	)

	var (
		makeLoader = func(envs map[string]string) env.Loader {
			return func(key string) string {
				return envs[key]
			}
		}
	)

	t.Run("it should configure correctly with auth disabled and defaults", func(t *testing.T) {
		conf, err := git.NewConf(makeLoader(map[string]string{
			"GIT_CLONE_REPO_URL":  repoURL,
			"GIT_CLONE_REFERENCE": reference,
		}))
		require.NoError(t, err)
		assert.Equal(t, repoURL, conf.RepoURL)
		assert.Equal(t, reference, conf.Reference)
	})

	t.Run("it should configure correctly with auth enabled and defaults", func(t *testing.T) {
		conf, err := git.NewConf(makeLoader(map[string]string{
			"GIT_CLONE_REPO_URL":        repoURL,
			"GIT_CLONE_REFERENCE":       reference,
			"GIT_CLONE_AUTH_ENABLED":    "true",
			"GIT_CLONE_ACCESS_TOKEN":    accessToken,
			"GIT_CLONE_ACCESS_USERNAME": accessUsername,
		}))
		require.NoError(t, err)
		assert.Equal(t, repoURL, conf.RepoURL)
		assert.Equal(t, reference, conf.Reference)
		assert.True(t, conf.ConfAuth.AuthEnabled)
		assert.Equal(t, accessToken, conf.ConfAuth.AccessToken)
		assert.Equal(t, accessUsername, conf.ConfAuth.Username)
	})

	t.Run("it should configure correctly with all overrides and no defaults", func(t *testing.T) {
		conf, err := git.NewConf(makeLoader(map[string]string{
			"GIT_CLONE_PATH":            clonePath,
			"GIT_CLONE_REPO_URL":        repoURL,
			"GIT_CLONE_REFERENCE":       reference,
			"GIT_CLONE_AUTH_ENABLED":    "true",
			"GIT_CLONE_ACCESS_TOKEN":    accessToken,
			"GIT_CLONE_ACCESS_USERNAME": accessUsername,
		}))
		require.NoError(t, err)
		assert.Equal(t, clonePath, conf.ClonePath)
		assert.Equal(t, repoURL, conf.RepoURL)
		assert.Equal(t, reference, conf.Reference)
		assert.True(t, conf.ConfAuth.AuthEnabled)
		assert.Equal(t, accessToken, conf.ConfAuth.AccessToken)
		assert.Equal(t, accessUsername, conf.ConfAuth.Username)
	})
}

func TestNewManager(t *testing.T) {
	const (
		clonePath      = "/workspace"
		repoURL        = "https://github.com/andream16/go-opentracing-example"
		reference      = "main"
		accessToken    = "superSecureToken"
		accessUsername = "andrea@smithy.security"
	)

	for _, tt := range []struct {
		testCase   string
		conf       *git.Conf
		expectsErr bool
	}{
		{
			testCase: "it should return an error because the repo url is empty",
			conf: &git.Conf{
				ClonePath: clonePath,
				Reference: reference,
				ConfAuth: git.ConfAuth{
					AuthEnabled: true,
					AccessToken: accessToken,
					Username:    accessUsername,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because the branch is empty",
			conf: &git.Conf{
				ClonePath: clonePath,
				RepoURL:   repoURL,
				ConfAuth: git.ConfAuth{
					AuthEnabled: true,
					AccessToken: accessToken,
					Username:    accessUsername,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because auth is on but the access token is empty",
			conf: &git.Conf{
				ClonePath: clonePath,
				Reference: reference,
				RepoURL:   repoURL,
				ConfAuth: git.ConfAuth{
					AuthEnabled: true,
					Username:    accessUsername,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because auth is on but the access username is empty",
			conf: &git.Conf{
				ClonePath: clonePath,
				Reference: reference,
				RepoURL:   repoURL,
				ConfAuth: git.ConfAuth{
					AuthEnabled: true,
					AccessToken: accessToken,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return a valid manager with no auth configured",
			conf: &git.Conf{
				ClonePath: clonePath,
				RepoURL:   repoURL,
				Reference: reference,
			},
		},
		{
			testCase: "it should return a valid manager with all options configured",
			conf: &git.Conf{
				ClonePath: clonePath,
				RepoURL:   repoURL,
				Reference: reference,
				ConfAuth: git.ConfAuth{
					AuthEnabled: true,
					AccessToken: accessToken,
					Username:    accessUsername,
				},
			},
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			mgr, err := git.NewManager(tt.conf)
			if tt.expectsErr {
				require.Error(t, err)
				require.Nil(t, mgr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, mgr)
		})
	}
}
