package git_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/targets/git-clone/pkg/git"
)

func TestNewManager(t *testing.T) {
	const (
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
			testCase: "it should return an error because the Repo url is empty",
			conf: &git.Conf{
				Reference: reference,
				ConfAuth: git.ConfAuth{
					AccessToken: accessToken,
					Username:    accessUsername,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because username is set but the access token is empty",
			conf: &git.Conf{
				Reference: reference,
				RepoURL:   repoURL,
				ConfAuth: git.ConfAuth{
					Username: accessUsername,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because access token is set but the access username is empty",
			conf: &git.Conf{
				Reference: reference,
				RepoURL:   repoURL,
				ConfAuth: git.ConfAuth{
					AccessToken: accessToken,
				},
			},
			expectsErr: true,
		},
		{
			testCase: "it should return a valid Manager with no auth configured",
			conf: &git.Conf{
				RepoURL:   repoURL,
				Reference: reference,
			},
		},
		{
			testCase: "it should return a valid Manager with all options configured",
			conf: &git.Conf{
				RepoURL:   repoURL,
				Reference: reference,
				ConfAuth: git.ConfAuth{
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
