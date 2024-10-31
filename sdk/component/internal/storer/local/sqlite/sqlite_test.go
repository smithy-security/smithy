package sqlite_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/storer"
	"github.com/smithy-security/smithy/sdk/component/internal/storer/local/sqlite"
	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

const (
	dbName = "smithy.db"
)

type (
	localStorer interface {
		component.Closer
		component.Reader
		component.Updater
		component.Writer

		CreateTable() error
	}

	ManagerTestSuite struct {
		suite.Suite

		t       *testing.T
		manager localStorer
	}
)

func (mts *ManagerTestSuite) SetupTest() {
	mts.t = mts.T()
	var (
		err   error
		clock = clockwork.NewFakeClock()
	)

	f, err := os.Create(dbName)
	require.NoError(mts.t, err)
	require.NoError(mts.t, f.Close())

	mts.manager, err = sqlite.NewManager("smithy.db", sqlite.ManagerWithClock(clock))
	require.NoError(mts.t, err)
	require.NoError(mts.T(), mts.manager.CreateTable())
}

func (mts *ManagerTestSuite) TearDownTest() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(mts.t, mts.manager.Close(ctx))
	require.NoError(mts.t, os.Remove(dbName))
}

func (mts *ManagerTestSuite) TestManager() {
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

	mts.t.Run("given an empty database, when I look for findings, I get none back", func(t *testing.T) {
		resFindings, err := mts.manager.Read(
			ctx,
			instanceID,
		)
		require.ErrorIs(t, err, storer.ErrNoFindingsFound)
		require.Len(mts.t, resFindings, 0)
	})

	mts.t.Run("given an empty database, I should be able to create two findings", func(t *testing.T) {
		require.NoError(
			mts.t,
			mts.manager.Write(
				ctx,
				instanceID,
				findings,
			),
		)
	})

	mts.t.Run("given findings for an existing instance exist, a second write will fail", func(t *testing.T) {
		require.Error(
			mts.t,
			mts.manager.Write(
				ctx,
				instanceID,
				findings,
			),
		)
	})

	mts.t.Run("given two findings are present in the database, I should be able to retrieve them", func(t *testing.T) {
		resFindings, err := mts.manager.Read(ctx, instanceID)
		require.NoError(mts.t, err)
		require.Len(mts.t, resFindings, 2)
		assert.EqualValues(mts.t, findings, resFindings)
	})

	mts.t.Run("given a non existing instance id in the database, updating should fail", func(t *testing.T) {
		require.ErrorIs(
			mts.t,
			mts.manager.Update(ctx, uuid.New(), findings),
			storer.ErrNoFindingsFound,
		)
	})

	mts.t.Run(
		"given the previous instance id, when I change metadata in the findings, I can update them correctly",
		func(t *testing.T) {
			const newVersion = "v1.1.0"

			copyFindings := append([]*ocsf.VulnerabilityFinding(nil), findings...)
			require.Len(mts.t, copyFindings, 2)
			copyFindings[0].Metadata.Version = newVersion
			copyFindings[1].Metadata.Version = newVersion

			require.NoError(
				mts.t,
				mts.manager.Update(ctx, instanceID, copyFindings),
			)

			resFindings, err := mts.manager.Read(ctx, instanceID)
			require.NoError(mts.t, err)
			require.Len(mts.t, resFindings, 2)
			assert.EqualValues(mts.t, copyFindings, resFindings)
		})
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

func ptr[T any](v T) *T {
	return &v
}
