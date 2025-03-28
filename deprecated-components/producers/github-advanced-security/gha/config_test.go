package gha

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClientConfig(t *testing.T) {
	testCases := []struct {
		name        string
		config      *ClientConfig
		expectedErr error
	}{
		{
			name:        "no repo owner returns an error",
			config:      &ClientConfig{},
			expectedErr: ErrNoRepositoryOwner,
		},
		{
			name: "no repo name returns an error",
			config: &ClientConfig{
				RepositoryOwner: "smithy-security",
			},
			expectedErr: ErrNoRepositoryName,
		},
		{
			name: "no token returns an error",
			config: &ClientConfig{
				RepositoryOwner: "smithy-security",
				RepositoryName:  "smithy",
			},
			expectedErr: ErrNoOauth2TokenProvided,
		},
		{
			name: "no ref returns an error",
			config: &ClientConfig{
				RepositoryOwner: "smithy-security",
				RepositoryName:  "smithy",
				Token:           "bla",
			},
			expectedErr: ErrNoRef,
		},
		{
			name: "severity is parsed correctly",
			config: &ClientConfig{
				RepositoryOwner: "smithy-security",
				RepositoryName:  "smithy",
				Token:           "bla",
				Ref:             "refs/pull/735/head",
				Severity:        "bla",
			},
			expectedErr: ErrWrongSeverity,
		},
		{
			name: "wrong request timeout returns an error",
			config: &ClientConfig{
				RepositoryOwner:   "smithy-security",
				RepositoryName:    "smithy",
				Token:             "bla",
				Ref:               "refs/pull/735/head",
				Severity:          "low",
				RequestTimeoutStr: "bla",
			},
			expectedErr: ErrWrongRequestTimeoutDuration,
		},
		{
			name: "wrong page size returns an error",
			config: &ClientConfig{
				RepositoryOwner:   "smithy-security",
				RepositoryName:    "smithy",
				Token:             "bla",
				Ref:               "refs/pull/735/head",
				Severity:          "low",
				RequestTimeoutStr: "30s",
				PageSizeStr:       "bla",
			},
			expectedErr: ErrCouldNotParsePageSize,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.ErrorIs(t, testCase.config.Parse(), testCase.expectedErr)
		})
	}

	correctConfig := &ClientConfig{
		RepositoryOwner:   "smithy-security",
		RepositoryName:    "smithy",
		Token:             "bla",
		Ref:               "refs/pull/735/head",
		Severity:          "low",
		RequestTimeoutStr: "30s",
		PageSizeStr:       "10",
	}
	require.NoError(t, correctConfig.Parse())
	require.Equal(t, 10, correctConfig.PageSize)
	require.Equal(t, 30*time.Second, correctConfig.RequestTimeout)
}
