package annotation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/smithy-security/pkg/utils"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/smithy-security/smithy/components/enrichers/custom-annotation/internal/annotation"
)

func TestCustomAnnotator_Annotate(t *testing.T) {
	const annotationName = "foobar"

	var (
		ctx, cancel      = context.WithTimeout(context.Background(), time.Second)
		now              = time.Now().Unix()
		annotationValues = map[string]string{
			"teams":                "internal",
			"business-criticality": "yes",
		}
		conf = &annotation.Conf{
			AnnotationName:   annotationName,
			AnnotationValues: annotationValues,
		}
		vulns = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
					CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
					ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
					Confidence:   utils.Ptr("MEDIUM"),
					ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
					Count:        utils.Ptr(int32(1)),
					FindingInfo: &ocsf.FindingInfo{
						CreatedTime: &now,
						DataSources: []string{
							"/main.go",
						},
						Desc:          utils.Ptr("lots of hacks"),
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						ModifiedTime:  &now,
						ProductUid:    utils.Ptr("gosec"),
						Title:         "You have lots of issues",
						Uid:           "1",
					},
					Message: utils.Ptr("lots of hacks"),
					Resource: &ocsf.ResourceDetails{
						Uid: utils.Ptr(
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
					RawData:    utils.Ptr(`{"issues" : []}`),
					Severity:   utils.Ptr("CRITICAL"),
					SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
					StartTime:  &now,
					Status:     utils.Ptr("opened"),
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
								SrcUrl: utils.Ptr("https://issues.com/1"),
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
					Confidence:   utils.Ptr("HIGH"),
					ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Count:        utils.Ptr(int32(2)),
					FindingInfo: &ocsf.FindingInfo{
						CreatedTime: &now,
						DataSources: []string{
							"/internal/sketchy/sketch.go",
						},
						Desc:          utils.Ptr("stop writing hacky code"),
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						ModifiedTime:  &now,
						ProductUid:    utils.Ptr("gosec"),
						Title:         "You have lots of hacky code",
						Uid:           "2",
					},
					Message: utils.Ptr("lots of hacky code"),
					Resource: &ocsf.ResourceDetails{
						Uid: utils.Ptr(
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
					RawData:    utils.Ptr(`{"issues" : [{"id": 2}]}`),
					Severity:   utils.Ptr("HIGH"),
					SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					StartTime:  &now,
					Status:     utils.Ptr("opened"),
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
								SrcUrl: utils.Ptr("https://issues.com/2"),
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
					Confidence:   utils.Ptr("LOW"),
					ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
					Count:        utils.Ptr(int32(3)),
					FindingInfo: &ocsf.FindingInfo{
						CreatedTime: &now,
						DataSources: []string{
							"/internal/sketchy/hacks.go",
						},
						Desc:          utils.Ptr("stop writing hacks"),
						FirstSeenTime: &now,
						LastSeenTime:  &now,
						ModifiedTime:  &now,
						ProductUid:    utils.Ptr("gosec"),
						Title:         "You have lots of hacks",
						Uid:           "3",
					},
					Message: utils.Ptr("lots of hacks"),
					Resource: &ocsf.ResourceDetails{
						Uid: utils.Ptr(
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
					RawData:    utils.Ptr(`{"issues" : [{"id": 3}]}`),
					Severity:   utils.Ptr("HIGH"),
					SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					StartTime:  &now,
					Status:     utils.Ptr("opened"),
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
								SrcUrl: utils.Ptr("https://issues.com/3"),
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

		for _, vuln := range enrichedVulns {
			require.NotNil(t, vuln)
			require.NotEmpty(t, vuln.Finding.Enrichments)
			for _, enrichment := range vuln.Finding.Enrichments {
				require.NotNil(t, enrichment)
				require.Equal(t, annotationName, enrichment.Name)
				require.Equal(t, "custom-annotation-enricher", *enrichment.Provider)
				require.Equal(t, "custom-annotation-enricher", *enrichment.Type)
				require.NotEmpty(t, enrichment.Value)
			}
		}
	})
}
