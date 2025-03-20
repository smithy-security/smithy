package registry_test

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithy/smithyctl/annotation"
	"github.com/smithy-security/smithy/smithyctl/registry"
	"github.com/smithy-security/smithy/smithyctl/utils"
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

func (suite *RegistryTestSuite) SetupSuite() {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
		err         error
	)

	defer cancel()

	suite.pool, err = dockertest.NewPool("")
	require.NoError(suite.T(), err)

	suite.registryResource, err = suite.pool.RunWithOptions(&dockertest.RunOptions{
		Name:       "registry",
		Platform:   "linux/amd64",
		Repository: "registry",
		Tag:        "2",
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
}

func (suite *RegistryTestSuite) TearDownSuite() {
	_ = suite.pool.Purge(suite.registryResource)
}

func (suite *RegistryTestSuite) TestPackageAndFetch() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	const (
		registryDestination = "manifests"
		registryAuthEnabled = false
		sdkVersion          = "v1.0.1"
		componentVersion    = "v3.2.1"
	)

	var (
		component = &v1.Component{
			Description: "Looks for truffles",
			Name:        "trufflehog",
			Parameters:  make([]v1.Parameter, 0),
			Steps:       make([]v1.Step, 0),
			Type:        v1.ComponentTypeScanner,
		}
		registryHost = suite.registryResource.GetHostPort("5000/tcp")
	)

	r, err := registry.New(
		registryHost,
		registryDestination,
		registryAuthEnabled,
		"",
		"",
	)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), r)

	require.NoError(
		suite.T(),
		r.Package(
			ctx,
			registry.PackageRequest{
				ComponentPath:    "scanners/trufflehog",
				Component:        component,
				SDKVersion:       sdkVersion,
				ComponentVersion: componentVersion,
			},
		),
	)

	ref, err := reference.Parse(
		path.Join(
			registryHost,
			registryDestination,
			utils.PluraliseComponentType(component.Type),
			component.Name+":"+componentVersion,
		),
	)
	require.NoError(suite.T(), err)

	resp, err := r.FetchPackage(ctx, ref)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), component, &resp.Component)
	assert.NotEmpty(suite.T(), resp.Annotations)
	assert.Contains(
		suite.T(),
		resp.Annotations,
		annotation.SmithySDKVersion,
		annotation.SmithyComponentDescr,
		annotation.SmithyComponentName,
		annotation.SmithyComponentType,
		annotation.SmithyComponentVersion,
		annotation.SmithyComponentSource,
		annotation.SmithyComponentURL,
	)
}

func TestNew(t *testing.T) {
	type newInput struct {
		registryHost         string
		registryDestination  string
		registryAuthEnabled  bool
		registryAuthUsername string
		registryAuthPassword string
	}

	const (
		registryHost         = "ghcr.io"
		registryDestination  = "manifests"
		registryAuthEnabled  = false
		registryAuthUsername = "smithy"
		registryAuthPassword = "smithy-secret-1234"
	)

	for _, tt := range []struct {
		testCase   string
		input      newInput
		expectsErr bool
	}{
		{
			testCase: "it should return an error because the registry host is empty",
			input: newInput{
				registryHost:         "",
				registryDestination:  registryDestination,
				registryAuthEnabled:  registryAuthEnabled,
				registryAuthUsername: registryAuthUsername,
				registryAuthPassword: registryAuthPassword,
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because the registry destination is empty",
			input: newInput{
				registryHost:         registryHost,
				registryDestination:  "",
				registryAuthEnabled:  registryAuthEnabled,
				registryAuthUsername: registryAuthUsername,
				registryAuthPassword: registryAuthPassword,
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because the auth username is empty",
			input: newInput{
				registryHost:         registryHost,
				registryDestination:  registryDestination,
				registryAuthEnabled:  true,
				registryAuthUsername: "",
				registryAuthPassword: registryAuthPassword,
			},
			expectsErr: true,
		},
		{
			testCase: "it should return an error because the auth password is empty",
			input: newInput{
				registryHost:         registryHost,
				registryDestination:  registryDestination,
				registryAuthEnabled:  true,
				registryAuthUsername: registryAuthUsername,
				registryAuthPassword: "",
			},
			expectsErr: true,
		},
		{
			testCase: "it should return a registry when auth is disabled and credentials are empty",
			input: newInput{
				registryHost:         registryHost,
				registryDestination:  registryDestination,
				registryAuthEnabled:  registryAuthEnabled,
				registryAuthUsername: "",
				registryAuthPassword: "",
			},
			expectsErr: false,
		},
		{
			testCase: "it should return a registry when auth is enabled and credentials are filled",
			input: newInput{
				registryHost:         registryHost,
				registryDestination:  registryDestination,
				registryAuthEnabled:  true,
				registryAuthUsername: registryAuthUsername,
				registryAuthPassword: registryAuthPassword,
			},
			expectsErr: false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			r, err := registry.New(
				tt.input.registryHost,
				tt.input.registryDestination,
				tt.input.registryAuthEnabled,
				tt.input.registryAuthUsername,
				tt.input.registryAuthPassword,
			)
			if tt.expectsErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, r)
		})
	}
}
