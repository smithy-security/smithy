package annotation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/components/enrichers/custom-annotation/internal/annotation"
)

func ptr[T any](v T) *T {
	return &v
}

func TestCustomAnnotator_Annotate(t *testing.T) {
	const annotationName = "reachability"

	var (
		ctx, cancel      = context.WithTimeout(context.Background(), time.Second)
		now              = time.Now().Unix()
		annotationValues = `{"paths" : {main.go": true, "internal/hacky.go": "true"}}`
		conf             = &annotation.Conf{
			AnnotationName:       annotationName,
			AnnotationValuesJSON: annotationValues,
		}
		vulns = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
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
			},
			{
				ID: 2,
				Finding: &ocsf.VulnerabilityFinding{
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
			},
			{
				ID: 3,
				Finding: &ocsf.VulnerabilityFinding{
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
			},
		}
	)

	defer cancel()

	t.Run("it should enrich the issues successfully", func(t *testing.T) {
		annotator, err := annotation.NewCustomAnnotator(conf)
		require.NoError(t, err)

		enrichedVulns, err := annotator.Annotate(ctx, vulns)
		require.NoError(t, err)
		require.Len(t, enrichedVulns, 3)
		assert.ElementsMatch(t, enrichedVulns, vulns)
	})
}
