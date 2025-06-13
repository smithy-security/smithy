package sqlite_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/store"
	localstore "github.com/smithy-security/smithy/sdk/component/store/local/sqlite"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	storer interface {
		component.Storer

		RemoveDatabase() error
	}

	ManagerTestSuite struct {
		suite.Suite

		t       *testing.T
		manager storer
	}
)

func (mts *ManagerTestSuite) SetupTest() {
	mts.t = mts.T()
	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		err         error
		clock       = clockwork.NewFakeClock()
	)

	defer cancel()
	mts.manager, err = localstore.NewManager(ctx, localstore.ManagerWithClock(clock))
	require.NoError(mts.t, err)
}

func (mts *ManagerTestSuite) TearDownTest() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(mts.t, mts.manager.Close(ctx))
	require.NoError(mts.t, mts.manager.RemoveDatabase())
}

func (mts *ManagerTestSuite) TestManager() {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		instanceID  = uuid.New()
		findings    = []*ocsf.VulnerabilityFinding{
			{
				ActivityId:      ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName:    utils.Ptr("Activity 1"),
				CategoryName:    utils.Ptr("Category A"),
				CategoryUid:     ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:       utils.Ptr("Class A"),
				ClassUid:        ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Cloud:           &ocsf.Cloud{Provider: "AWS", Region: utils.Ptr("us-west-2")},
				Comment:         utils.Ptr("This is a comment for finding 1."),
				Confidence:      utils.Ptr("High"),
				ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				ConfidenceScore: utils.Ptr(int32(95)),
				Count:           utils.Ptr(int32(1)),
				Duration:        utils.Ptr(int32(3600)),
				EndTime:         utils.Ptr(time.Now().Unix()),
				EndTimeDt:       timestamppb.New(time.Now()),
				Enrichments:     []*ocsf.Enrichment{{Type: utils.Ptr("Type1"), Value: "Value1"}},
				Message:         utils.Ptr("Vulnerability finding message 1"),
				Metadata: &ocsf.Metadata{
					Version: "v1.0.1",
				},
				RawData:         utils.Ptr(`{"foo" : "bar"}`),
				Severity:        utils.Ptr("Critical"),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:       utils.Ptr(time.Now().Add(-time.Hour).Unix()),
				StartTimeDt:     timestamppb.New(time.Now().Add(-time.Hour)),
				Status:          utils.Ptr("Open"),
				StatusCode:      utils.Ptr("200"),
				Time:            time.Now().Unix(),
				TimeDt:          timestamppb.New(time.Now()),
				TimezoneOffset:  utils.Ptr(int32(-7)),
				TypeName:        utils.Ptr("Type 1"),
				TypeUid:         1,
				Vulnerabilities: []*ocsf.Vulnerability{{Severity: utils.Ptr("Critical")}},
			},
			{
				ActivityId:      ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName:    utils.Ptr("Activity 2"),
				CategoryName:    utils.Ptr("Category B"),
				CategoryUid:     ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:       utils.Ptr("Class B"),
				ClassUid:        ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Cloud:           &ocsf.Cloud{Provider: "AWS", Region: utils.Ptr("us-east-2")},
				Comment:         utils.Ptr("This is a comment for finding 2."),
				Confidence:      utils.Ptr("High"),
				ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				ConfidenceScore: utils.Ptr(int32(100)),
				Count:           utils.Ptr(int32(5)),
				Duration:        utils.Ptr(int32(3600)),
				EndTime:         utils.Ptr(time.Now().Unix()),
				EndTimeDt:       timestamppb.New(time.Now()),
				Enrichments:     []*ocsf.Enrichment{{Type: utils.Ptr("Type2"), Value: "Value2"}},
				Message:         utils.Ptr("Vulnerability finding message 2"),
				Metadata: &ocsf.Metadata{
					Version: "v1.0.1",
				},
				RawData:         utils.Ptr(`{"bar" : "baz"}`),
				Severity:        utils.Ptr("Critical"),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:       utils.Ptr(time.Now().Add(-time.Hour).Unix()),
				StartTimeDt:     timestamppb.New(time.Now().Add(-time.Hour)),
				Status:          utils.Ptr("Closed"),
				StatusCode:      utils.Ptr("200"),
				Time:            time.Now().Unix(),
				TimeDt:          timestamppb.New(time.Now()),
				TimezoneOffset:  utils.Ptr(int32(-7)),
				TypeName:        utils.Ptr("Type 2"),
				TypeUid:         2,
				Vulnerabilities: []*ocsf.Vulnerability{{Severity: utils.Ptr("Critical")}},
			},
			{
				ActivityId:      ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName:    utils.Ptr("Activity 3"),
				CategoryName:    utils.Ptr("Category B"),
				CategoryUid:     ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:       utils.Ptr("Class B"),
				ClassUid:        ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Cloud:           &ocsf.Cloud{Provider: "AWS", Region: utils.Ptr("us-east-2")},
				Comment:         utils.Ptr("This is a comment for finding 3."),
				Confidence:      utils.Ptr("High"),
				ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				ConfidenceScore: utils.Ptr(int32(100)),
				Count:           utils.Ptr(int32(5)),
				Duration:        utils.Ptr(int32(3600)),
				EndTime:         utils.Ptr(time.Now().Unix()),
				EndTimeDt:       timestamppb.New(time.Now()),
				Enrichments:     []*ocsf.Enrichment{{Type: utils.Ptr("Type3"), Value: "Value3"}},
				Message:         utils.Ptr("Vulnerability finding message 3"),
				Metadata: &ocsf.Metadata{
					Version: "v1.0.1",
				},
				RawData:         utils.Ptr(`{"bar" : "baz"}`),
				Severity:        utils.Ptr("Critical"),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:       utils.Ptr(time.Now().Add(-time.Hour).Unix()),
				StartTimeDt:     timestamppb.New(time.Now().Add(-time.Hour)),
				Status:          utils.Ptr("Closed"),
				StatusCode:      utils.Ptr("200"),
				Time:            time.Now().Unix(),
				TimeDt:          timestamppb.New(time.Now()),
				TimezoneOffset:  utils.Ptr(int32(-7)),
				TypeName:        utils.Ptr("Type 3"),
				TypeUid:         3,
				Vulnerabilities: []*ocsf.Vulnerability{{Severity: utils.Ptr("Critical")}},
			},
		}
	)

	defer cancel()

	mts.t.Run("given an empty database, when I look for findings, I get none back", func(t *testing.T) {
		resFindings, err := mts.manager.Read(ctx, instanceID, nil)
		require.ErrorIs(t, err, store.ErrNoFindingsFound)
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

	mts.t.Run("given two findings are present in the database, I should be able to retrieve them", func(t *testing.T) {
		resFindings, err := mts.manager.Read(ctx, instanceID, nil)
		require.NoError(mts.t, err)
		require.Len(mts.t, resFindings, 3)

		assert.Equal(t, uint64(1), resFindings[0].ID)
		assert.Equal(mts.t, findings[0], resFindings[0].Finding)
		assert.Equal(t, uint64(2), resFindings[1].ID)
		assert.Equal(mts.t, findings[1], resFindings[1].Finding)
		assert.Equal(t, uint64(3), resFindings[2].ID)
		assert.Equal(mts.t, findings[2], resFindings[2].Finding)
	})

	mts.t.Run("given a non existing instance id in the database, updating should fail", func(t *testing.T) {
		require.ErrorIs(
			mts.t,
			mts.manager.Update(ctx, uuid.New(), []*vf.VulnerabilityFinding{
				{
					ID:      1,
					Finding: findings[0],
				},
			}),
			store.ErrNoFindingsFound,
		)
	})

	mts.t.Run(
		"given the previous instance id, when I change metadata in the findings, I can update them correctly",
		func(t *testing.T) {
			const newVersion = "v1.1.0"

			copyFindings := slices.Clone(findings)
			require.Len(mts.t, copyFindings, 3)
			copyFindings[0].Metadata.Version = newVersion
			copyFindings[1].Metadata.Version = newVersion

			require.NoError(
				mts.t,
				mts.manager.Update(ctx, instanceID, []*vf.VulnerabilityFinding{
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

			resFindings, err := mts.manager.Read(ctx, instanceID, nil)
			require.NoError(mts.t, err)
			require.Len(mts.t, resFindings, 3)

			assert.Equal(t, uint64(1), resFindings[0].ID)
			assert.Equal(mts.t, copyFindings[0], resFindings[0].Finding)
			assert.Equal(t, uint64(2), resFindings[1].ID)
			assert.Equal(mts.t, copyFindings[1], resFindings[1].Finding)
			assert.Equal(t, uint64(3), resFindings[2].ID)
			assert.Equal(mts.t, copyFindings[2], resFindings[2].Finding)
		},
	)

	mts.t.Run(
		"paging works as expected",
		func(t *testing.T) {
			resFindings, err := mts.manager.Read(ctx, instanceID, &store.QueryOpts{
				Page:     0,
				PageSize: 2,
			})
			require.NoError(t, err)
			require.Len(t, resFindings, 2)

			copyFindings := slices.Clone(findings)

			assert.Equal(t, uint64(1), resFindings[0].ID)
			assert.Equal(mts.t, copyFindings[0], resFindings[0].Finding)
			assert.Equal(t, uint64(2), resFindings[1].ID)
			assert.Equal(mts.t, copyFindings[1], resFindings[1].Finding)

			resFindings, err = mts.manager.Read(ctx, instanceID, &store.QueryOpts{
				Page:     1,
				PageSize: 2,
			})
			require.NoError(t, err)
			require.Len(t, resFindings, 1)

			assert.Equal(t, uint64(3), resFindings[0].ID)
			assert.Equal(mts.t, copyFindings[2], resFindings[0].Finding)

			resFindings, err = mts.manager.Read(ctx, instanceID, &store.QueryOpts{
				Page:     10,
				PageSize: 2,
			})
			require.ErrorIs(t, err, store.ErrNoFindingsFound)
			require.Empty(t, resFindings)
		},
	)
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}
