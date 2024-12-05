package postgresql_test

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/store/remote/postgresql"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	Storer interface {
		component.Storer
		Ping(ctx context.Context) error
	}

	ManagerTestSuite struct {
		suite.Suite

		pool          *dockertest.Pool
		psqlResource  *dockertest.Resource
		atlasResource *dockertest.Resource
		dockerNetwork *docker.Network

		manager Storer
	}
)

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

func (suite *ManagerTestSuite) SetupSuite() {
	const (
		user     = "smithy"
		password = "smithy1234"
		dbName   = "smithy-findings"
	)

	var (
		err         error
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(
			time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC),
		)
	)
	defer cancel()

	suite.pool, err = dockertest.NewPool("")
	require.NoError(suite.T(), err)

	suite.dockerNetwork, err = suite.pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:   "test-network",
		Driver: "bridge",
	})
	require.NoError(suite.T(), err)

	suite.psqlResource, err = suite.pool.RunWithOptions(&dockertest.RunOptions{
		Name:       "postgres",
		Platform:   "linux/amd64",
		Repository: "postgres",
		Tag:        "15",
		Env: []string{
			fmt.Sprintf("POSTGRES_USER=%s", user),
			fmt.Sprintf("POSTGRES_PASSWORD=%s", password),
			fmt.Sprintf("POSTGRES_DB=%s", dbName),
		},
		NetworkID: suite.dockerNetwork.ID,
	}, func(config *docker.HostConfig) {})

	var (
		psqlDockerPort = suite.psqlResource.GetPort("5432/tcp")
		psqlDSN        = fmt.Sprintf(
			"postgresql://%s:%s@localhost:%s/%s?sslmode=disable&connect_timeout=10",
			user,
			password,
			psqlDockerPort,
			dbName,
		)
	)

	require.NoError(suite.T(), suite.pool.Retry(func() error {
		pingCtx, pingCancel := context.WithTimeout(ctx, time.Second)
		defer pingCancel()
		suite.manager, err = postgresql.NewManager(
			ctx,
			postgresql.ManagerWithClock(clock),
			postgresql.ManagerWithConnDSN(psqlDSN),
		)
		if err != nil {
			return err
		}
		return suite.manager.Ping(pingCtx)
	}))

	p, err := filepath.Abs(".")
	require.NoError(suite.T(), err)

	var (
		migrationsPath  = path.Join(p, "sqlc/migrations")
		psqlExternalDSN = fmt.Sprintf(
			"postgresql://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=10",
			user,
			password,
			strings.TrimPrefix(suite.psqlResource.Container.Name, "/"),
			5432,
			dbName,
		)
	)

	suite.atlasResource, err = suite.pool.RunWithOptions(&dockertest.RunOptions{
		Name:       "atlas-migrator",
		Platform:   "linux/amd64",
		Repository: "arigaio/atlas",
		Tag:        "latest-alpine",
		Cmd: []string{
			"migrate",
			"apply",
			"--dir",
			"file://migrations",
			"--url",
			psqlExternalDSN,
		},
		NetworkID: suite.dockerNetwork.ID,
	}, func(config *docker.HostConfig) {
		config.Binds = []string{fmt.Sprintf("%s:/migrations", migrationsPath)}
	})
	require.NoError(suite.T(), err)

	for {
		atlasContainer, err := suite.pool.Client.InspectContainer(suite.atlasResource.Container.ID)
		require.NoError(suite.T(), err)

		if !atlasContainer.State.Running {
			require.Equalf(
				suite.T(),
				0,
				atlasContainer.State.ExitCode,
				"unexpected atlas exit code: %d",
				atlasContainer.State.ExitCode,
			)
			break
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (suite *ManagerTestSuite) TearDownSuite() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(suite.T(), suite.manager.Close(ctx))
	_ = suite.pool.Purge(suite.atlasResource)
	_ = suite.pool.Purge(suite.psqlResource)
	_ = suite.pool.RemoveNetwork(&dockertest.Network{Network: suite.dockerNetwork})
}

func (suite *ManagerTestSuite) TestManager() {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		instanceID  = uuid.New()
		findings    = []*ocsf.VulnerabilityFinding{
			{
				ActivityId:      ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName:    ptr("Activity 1"),
				CategoryName:    ptr("Category A"),
				CategoryUid:     ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:       ptr("Class A"),
				ClassUid:        ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Cloud:           &ocsf.Cloud{Provider: "AWS", Region: ptr("us-west-2")},
				Comment:         ptr("This is a comment for finding 1."),
				Confidence:      ptr("High"),
				ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				ConfidenceScore: ptr(int32(95)),
				Count:           ptr(int32(1)),
				Duration:        ptr(int32(3600)),
				EndTime:         ptr(time.Now().Unix()),
				EndTimeDt:       timestamppb.New(time.Now()),
				Enrichments:     []*ocsf.Enrichment{{Type: ptr("Type1"), Value: "Value1"}},
				Message:         ptr("Vulnerability finding message 1"),
				Metadata: &ocsf.Metadata{
					Version: "v1.0.1",
				},
				RawData:         ptr(`{"foo" : "bar"}`),
				Severity:        ptr("Critical"),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:       ptr(time.Now().Add(-time.Hour).Unix()),
				StartTimeDt:     timestamppb.New(time.Now().Add(-time.Hour)),
				Status:          ptr("Open"),
				StatusCode:      ptr("200"),
				Time:            time.Now().Unix(),
				TimeDt:          timestamppb.New(time.Now()),
				TimezoneOffset:  ptr(int32(-7)),
				TypeName:        ptr("Type 1"),
				TypeUid:         1,
				Vulnerabilities: []*ocsf.Vulnerability{{Severity: ptr("Critical")}},
			},
			{
				ActivityId:      ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName:    ptr("Activity 2"),
				CategoryName:    ptr("Category B"),
				CategoryUid:     ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:       ptr("Class B"),
				ClassUid:        ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Cloud:           &ocsf.Cloud{Provider: "AWS", Region: ptr("us-east-2")},
				Comment:         ptr("This is a comment for finding 2."),
				Confidence:      ptr("High"),
				ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				ConfidenceScore: ptr(int32(100)),
				Count:           ptr(int32(5)),
				Duration:        ptr(int32(3600)),
				EndTime:         ptr(time.Now().Unix()),
				EndTimeDt:       timestamppb.New(time.Now()),
				Enrichments:     []*ocsf.Enrichment{{Type: ptr("Type2"), Value: "Value2"}},
				Message:         ptr("Vulnerability finding message 2"),
				Metadata: &ocsf.Metadata{
					Version: "v1.0.1",
				},
				RawData:         ptr(`{"bar" : "baz"}`),
				Severity:        ptr("Critical"),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:       ptr(time.Now().Add(-time.Hour).Unix()),
				StartTimeDt:     timestamppb.New(time.Now().Add(-time.Hour)),
				Status:          ptr("Closed"),
				StatusCode:      ptr("200"),
				Time:            time.Now().Unix(),
				TimeDt:          timestamppb.New(time.Now()),
				TimezoneOffset:  ptr(int32(-7)),
				TypeName:        ptr("Type 2"),
				TypeUid:         2,
				Vulnerabilities: []*ocsf.Vulnerability{{Severity: ptr("Critical")}},
			},
		}
	)

	defer cancel()

	suite.T().Run("given an empty findings table, I shouldn't find any for an instanceID", func(t *testing.T) {
		f, err := suite.manager.Read(ctx, instanceID)
		require.ErrorIs(t, err, store.ErrNoFindingsFound)
		assert.Empty(t, f)
	})

	suite.T().Run("given two valid findings, I should be able to write it successfully", func(t *testing.T) {
		require.NoError(t, suite.manager.Write(ctx, instanceID, findings))
	})

	suite.T().Run("given two findings are present in the database, I should be able to retrieve them", func(t *testing.T) {
		resFindings, err := suite.manager.Read(ctx, instanceID)
		require.NoError(t, err)
		require.Len(t, resFindings, 2)

		assert.Equal(t, uint64(1), resFindings[0].ID)
		assert.Equal(t, findings[0], resFindings[0].Finding)
		assert.Equal(t, uint64(2), resFindings[1].ID)
		assert.Equal(t, findings[1], resFindings[1].Finding)
	})

	suite.T().Run(
		"given the previous instance id, when I change metadata in the findings, I can update them correctly",
		func(t *testing.T) {
			const newVersion = "v1.1.0"

			copyFindings := append([]*ocsf.VulnerabilityFinding(nil), findings...)
			require.Len(t, copyFindings, 2)
			copyFindings[0].Metadata.Version = newVersion
			copyFindings[1].Metadata.Version = newVersion

			require.NoError(
				t,
				suite.manager.Update(ctx, instanceID, []*vf.VulnerabilityFinding{
					{
						ID:      1,
						Finding: copyFindings[0],
					},
					{
						ID:      2,
						Finding: copyFindings[1],
					},
				}),
			)

			resFindings, err := suite.manager.Read(ctx, instanceID)
			require.NoError(t, err)
			require.Len(t, resFindings, 2)

			assert.Equal(t, uint64(1), resFindings[0].ID)
			assert.Equal(t, copyFindings[0], resFindings[0].Finding)
			assert.Equal(t, uint64(2), resFindings[1].ID)
			assert.Equal(t, copyFindings[1], resFindings[1].Finding)
		})
}

func ptr[T any](v T) *T {
	return &v
}
