package reporter

import (
	"context"
	"testing"
	"time"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func ptr[T any](v T) *T {
	return &v
}

var now = time.Now().Unix()

func getData(t *testing.T) []*vf.VulnerabilityFinding {
	ds := []*ocsffindinginfo.DataSource{
		{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   1,
					EndLine:     10,
					StartColumn: 1,
					EndColumn:   10,
				},
			},
			Uri: ptr(ocsffindinginfo.DataSource_URI{
				Path: "https://github.com/foo/bar",
			}),
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "https://github.com/foo/bar",
				Reference:     "refs/heads/main",
			},
		},
		{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
			Uri: ptr(ocsffindinginfo.DataSource_URI{
				Path: "https://github.com/foo/bar",
			}),
			OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
				PackageUrl: "oci://registry.example.com/foo/bar",
				Tag:        "latest",
			},
		},
	}
	datasources := []string{}
	for _, ds := range ds {
		a, err := protojson.Marshal(ds)
		require.NoError(t, err)
		datasources = append(datasources, string(a))
	}

	return []*vf.VulnerabilityFinding{
		{
			Finding: &ocsf.VulnerabilityFinding{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("MEDIUM"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
				Count:        ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   &now,
					DataSources:   datasources,
					Desc:          ptr("lots of hacks"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of issues",
					Uid:           "1",
				},
				Message:    ptr("lots of hacks"),
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
			Finding: &ocsf.VulnerabilityFinding{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("HIGH"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        ptr(int32(2)),
				Enrichments: []*ocsf.Enrichment{
					{
						Provider: ptr("foo"),
						Value:    "bar",
						Name:     "baz",
						Type:     ptr("qux"),
					},
					{
						Provider: ptr("foo1"),
						Value:    "bar2",
						Name:     "baz3",
						Type:     ptr("qux4"),
					},
				},
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   &now,
					Desc:          ptr("stop writing hacky code"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of hacky code",
					Uid:           "2",
				},
				Message:    ptr("lots of hacky code"),
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
			Finding: &ocsf.VulnerabilityFinding{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("LOW"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
				Count:        ptr(int32(3)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   &now,
					Desc:          ptr("stop writing hacks"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of hacks",
					Uid:           "3",
				},
				Message:    ptr("lots of hacks"),
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
}

func TestReporter(t *testing.T) {
	tests := []struct {
		name        string
		input       []*vf.VulnerabilityFinding // Replace with actual input type
		expected    string                     // Replace with actual expected type
		expectError bool
	}{
		{
			name:        "Valid input case",
			input:       getData(t),
			expected:    "Expected output for valid input",
			expectError: false,
		},
	}
	vR := vulnReporter{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function from reporter.go
			err := vR.Report(context.Background(), tt.input) /* Function call with tt.input */

			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}
