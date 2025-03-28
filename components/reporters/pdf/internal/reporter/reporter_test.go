package reporter

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	playwright "github.com/smithy-security/smithy/pkg/playwright/mock"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func TestPdfReporter(t *testing.T) {
	t.Run("The config should initialize correctly", func(t *testing.T) {
		err := os.Setenv("SMITHY_INSTANCE_ID", "my-awesome-instance-id")
		require.NoError(t, err)
		err = os.Setenv("SKIP_S3_UPLOAD", "true")
		require.NoError(t, err)
		err = os.Setenv("BUCKET_NAME", "test-bucket")
		require.NoError(t, err)
		err = os.Setenv("BUCKET_REGION", "us-west-1")
		require.NoError(t, err)

		conf, err := NewConf(nil)
		require.NoError(t, err)
		assert.Equal(t, "test-bucket", conf.Bucket)
		assert.Equal(t, "us-west-1", conf.Region)
		assert.True(t, conf.SkipS3Upload)
	})

	t.Run("it should build a PDF", func(t *testing.T) {
		// set up test data
		now := time.Now().Unix()
		findings := getTestData(now)

		// set up the reporter component
		conf := &Conf{
			InstanceId:   "my-awesome-instance-id",
			Bucket:       "test-bucket",
			Region:       "us-west-1",
			SkipS3Upload: true,
		}
		reporter := NewReporter(conf)

		// set up the mock playwright
		mockClient, err := playwright.NewMockClient()
		require.NoError(t, err)
		expected := []byte("this is a pdf")
		mockClient.GetPDFOfPageCallBack = func(s1, s2 string) ([]byte, error) {
			return expected, nil
		}

		// check if the PDF builds
		_, result, err := reporter.buildPdf(findings, mockClient)
		require.NoError(t, err)
		require.Equal(t, result, expected)
	})

	t.Run("the time formatting function for the PDF template should work", func(t *testing.T) {
		timestamp := int64(1672531199) // Example timestamp
		formattedTime := FormatTime(&timestamp)
		expectedTime := time.Unix(timestamp, 0).Format(time.DateTime)
		assert.Equal(t, expectedTime, formattedTime)
	})
}

func ptr[T any](v T) *T {
	return &v
}

func getTestData(now int64) []*vf.VulnerabilityFinding {
	vulns := []*ocsf.VulnerabilityFinding{
		{
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			Confidence:   ptr("MEDIUM"),
			ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
			Count:        ptr(int32(1)),
			FindingInfo: &ocsf.FindingInfo{
				CreatedTime: &now,
				DataSources: []string{
					"/main.go",
				},
				Desc:          ptr("lots of hacks"),
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				ModifiedTime:  &now,
				ProductUid:    ptr("gosec"),
				Title:         "You have lots of issues",
				Uid:           "1",
			},
			Message: ptr("lots of hacks"),
			Resource: &ocsf.ResourceDetails{
				Uid: ptr(
					strings.Join([]string{
						"/main.go",
						"1",
						"1",
					},
						":",
					),
				),
				Data: &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: "1",
					},
				},
			},
			RawData:    ptr(`{"issues" : []}`),
			Severity:   ptr("CRITICAL"),
			SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
			StartTime:  &now,
			Status:     ptr("opened"),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					Cwe: &ocsf.Cwe{
						Uid:    "1",
						SrcUrl: ptr("https://issues.com/1"),
					},
				},
			},
		},
		{
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			Confidence:   ptr("HIGH"),
			ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
			Count:        ptr(int32(2)),
			FindingInfo: &ocsf.FindingInfo{
				CreatedTime: &now,
				DataSources: []string{
					"/internal/sketchy/sketch.go",
				},
				Desc:          ptr("stop writing hacky code"),
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				ModifiedTime:  &now,
				ProductUid:    ptr("gosec"),
				Title:         "You have lots of hacky code",
				Uid:           "2",
			},
			Message: ptr("lots of hacky code"),
			Resource: &ocsf.ResourceDetails{
				Uid: ptr(
					strings.Join([]string{
						"/internal/sketchy/sketch.go",
						"10",
						"1",
					},
						":",
					),
				),
				Data: &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: "2",
					},
				},
			},
			RawData:    ptr(`{"issues" : [{"id": 2}]}`),
			Severity:   ptr("HIGH"),
			SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
			StartTime:  &now,
			Status:     ptr("opened"),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					Cwe: &ocsf.Cwe{
						Uid:    "2",
						SrcUrl: ptr("https://issues.com/2"),
					},
				},
			},
		},
		{
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			Confidence:   ptr("LOW"),
			ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
			Count:        ptr(int32(3)),
			FindingInfo: &ocsf.FindingInfo{
				CreatedTime: &now,
				DataSources: []string{
					"/internal/sketchy/hacks.go",
				},
				Desc:          ptr("stop writing hacks"),
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				ModifiedTime:  &now,
				ProductUid:    ptr("gosec"),
				Title:         "You have lots of hacks",
				Uid:           "3",
			},
			Message: ptr("lots of hacks"),
			Resource: &ocsf.ResourceDetails{
				Uid: ptr(
					strings.Join([]string{
						"/internal/sketchy/hacks.go",
						"123",
						"13",
					},
						":",
					),
				),
				Data: &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: "3",
					},
				},
			},
			RawData:    ptr(`{"issues" : [{"id": 3}]}`),
			Severity:   ptr("HIGH"),
			SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
			StartTime:  &now,
			Status:     ptr("opened"),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					Cwe: &ocsf.Cwe{
						Uid:    "3",
						SrcUrl: ptr("https://issues.com/3"),
					},
				},
			},
		},
	}
	findings := []*vf.VulnerabilityFinding{
		{
			ID:      0,
			Finding: vulns[0],
		},
		{
			ID:      1,
			Finding: vulns[1],
		},
		{
			ID:      2,
			Finding: vulns[2],
		},
	}
	return findings
}
