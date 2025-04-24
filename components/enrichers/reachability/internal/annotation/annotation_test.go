package annotation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/conf"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func ptr[T any](v T) *T {
	return &v
}

func TestReachability_Annotate(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		now         = time.Now().Unix()

		conf = conf.Conf{
			ATOMFileGlob: "../../testdata/*atom.json",
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
							VendorName: ptr("tests"),
							AffectedCode: []*ocsf.AffectedCode{
								{
									StartLine: ptr(int32(67)),
									EndLine:   ptr(int32(67)),
									File: &ocsf.File{
										Path: ptr("bandit-env/lib/python3.12/site-packages/flask/ctx.py"),
									},
								},
							},
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
						// remove product uid use case
						Title: "You have lots of hacky code",
						Uid:   "2",
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
							VendorName: ptr("tests"),
							Cve: &ocsf.Cve{
								Cvss: []*ocsf.Cvss{{BaseScore: 6}},
								Uid:  "CVE-2000-001",
							},
							AffectedPackages: []*ocsf.AffectedPackage{
								{
									Purl: ptr("pkg:pypi/flask@3.0.3"),
								},
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
						Title:         "You have lots of hacks",
						// remove product uid use case but add metadata
						Uid: "3",
					},
					Message: ptr("lots of hacks"),
					Metadata: &ocsf.Metadata{
						Product: &ocsf.Product{
							Name: ptr("tests"),
						},
					},
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
					Vulnerabilities: []*ocsf.Vulnerability{ // unreachable vulnerability
						{
							VendorName: ptr("tests"),
							AffectedCode: []*ocsf.AffectedCode{
								{
									StartLine: ptr(int32(466)),
									EndLine:   ptr(int32(466)),
									File: &ocsf.File{
										Path: ptr("/foo/bar"),
									},
								},
							},
							Cwe: &ocsf.Cwe{
								Uid:    "1",
								SrcUrl: ptr("https://issues.com/1"),
							},
						},
					},
				},
			},
		}
	)

	defer cancel()

	t.Run("it should enrich the issues successfully", func(t *testing.T) {
		annotator := NewReachabilityAnnotator(&conf)

		enrichedVulns, err := annotator.Annotate(ctx, vulns)
		require.NoError(t, err)
		require.Len(t, enrichedVulns, 3)
		assert.Equal(
			t,
			[]*ocsf.Enrichment{
				{
					Name:     "Reachable-Code",
					Value:    "true",
					Provider: ptr("reachability-enricher"),
				},
			},
			enrichedVulns[0].Finding.Enrichments,
		)

		assert.Equal(
			t,
			[]*ocsf.Enrichment{
				{
					Name:     "Reachable-Code",
					Value:    "true",
					Provider: ptr("reachability-enricher"),
				},
			},
			enrichedVulns[1].Finding.Enrichments,
		)

		assert.Equal(
			t,
			[]*ocsf.Enrichment{
				{
					Name:     "Reachable-Code",
					Value:    "false",
					Provider: ptr("reachability-enricher"),
				},
			},
			enrichedVulns[2].Finding.Enrichments,
		)
	})
}
