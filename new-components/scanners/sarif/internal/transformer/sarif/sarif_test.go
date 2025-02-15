package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/new-components/scanners/sarif/internal/util/ptr"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func Test_ParseOut(t *testing.T) {
	t.Run("gosec testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/gosec_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		now := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"file://main.go\"},\"fileFindingLocationData\":{\"startLine\":83,\"startColumn\":7}}",
					},
					Desc:  ptr.Ptr("[test for missing endLine, common in some tools]"),
					Title: "[test for missing endLine, common in some tools]",
				},
				Message: ptr.Ptr("[test for missing endLine, common in some tools]"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
							},
						},
						Desc:       ptr.Ptr("[test for missing endLine, common in some tools]"),
						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("[test for missing endLine, common in some tools]"),
						VendorName: ptr.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"file://main.go\"},\"fileFindingLocationData\":{\"startLine\":83,\"endLine\":83,\"startColumn\":7,\"endColumn\":7}}",
					},
					Desc:  ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
					Title: "Use of weak random number generator (math/rand instead of crypto/rand)",
				},
				Message: ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
								EndLine:   ptr.Ptr(int32(83)),
							},
						},
						Desc:       ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						VendorName: ptr.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"file://main.go\"},\"fileFindingLocationData\":{\"startLine\":83}}",
					},
					Desc:  ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
					Title: "Use of weak random number generator (math/rand instead of crypto/rand) - nil endline",
				},
				Message: ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
							},
						},
						Desc:       ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						VendorName: ptr.Ptr("gosec"),
					},
				},
			},
		}
		transformer, err := NewSarifTransformer(&sarifOutput, "", TargetTypeRepository, clock)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})
	t.Run("snyk-node testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/snyk-node_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		now := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources:   []string{"{\"fileFindingLocationData\":{\"startLine\":1}}"},
					Desc:          ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
					Title:         "This file introduces a vulnerable cookie package with a medium severity vulnerability.",
				},
				Message: ptr.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-COOKIE-8163060"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "cookie",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/cookie@0.3.1"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
							Uid:  "CVE-2024-47764",
						},
						Desc:           ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
						FixAvailable:   ptr.Ptr(true),
						IsFixAvailable: ptr.Ptr(true),
						Severity:       ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:          ptr.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability."),
						VendorName:     ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources:   []string{"{\"fileFindingLocationData\":{\"startLine\":1}}"},
					Desc:          ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
					Title:         "This file introduces a vulnerable engine.io package with a high severity vulnerability.",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-1056749"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
							Uid:  "CVE-2020-36048",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:           ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
						FixAvailable:   ptr.Ptr(true),
						IsFixAvailable: ptr.Ptr(true),
						Severity:       ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:          ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
						VendorName:     ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources:   []string{"{\"fileFindingLocationData\":{\"startLine\":1}}"},
					Desc:          ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
					Title:         "This file introduces a vulnerable engine.io package with a high severity vulnerability.",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-3136336"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
							Uid:  "CVE-2022-41940",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:           ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
						FixAvailable:   ptr.Ptr(true),
						IsFixAvailable: ptr.Ptr(true),
						Severity:       ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:          ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
						VendorName:     ptr.Ptr("Snyk Open Source"),
					},
				},
			},
		}
		transformer, err := NewSarifTransformer(&sarifOutput, "npm", TargetTypeDependency, clock)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)

	})
	t.Run("codeql testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/code-ql.sarif.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		now := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://components/consumers/defectdojo/main.go\"}, \"fileFindingLocationData\":{\"startLine\":53, \"startColumn\":103, \"endColumn\":117}}",
					},
					Desc:  ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					Title: "go/incorrect-integer-conversion",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: ptr.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: ptr.Ptr(int32(53)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:       ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("go/incorrect-integer-conversion"),
						VendorName: ptr.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://components/consumers/defectdojo/main.go\"}, \"fileFindingLocationData\":{\"startLine\":106, \"startColumn\":103, \"endColumn\":117}}",
					},
					Desc:  ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					Title: "go/incorrect-integer-conversion",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: ptr.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: ptr.Ptr(int32(106)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:       ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("go/incorrect-integer-conversion"),
						VendorName: ptr.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://components/producers/github-codeql/main.go\"}, \"fileFindingLocationData\":{\"startLine\":209, \"startColumn\":24, \"endColumn\":34}}",
					},
					Desc:  ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					Title: "go/incorrect-integer-conversion",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/producers/github-codeql/main.go",
									Path: ptr.Ptr("file://components/producers/github-codeql/main.go"),
								},
								StartLine: ptr.Ptr(int32(209)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:       ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("go/incorrect-integer-conversion"),
						VendorName: ptr.Ptr("CodeQL"),
					},
				},
			},
		}
		transformer, err := NewSarifTransformer(&sarifOutput, "", TargetTypeRepository, clock)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)

	})
	t.Run("semgrep testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/semgrep.sarif.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		now := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://terragoat/terraform/aws/ec2.tf\"}, \"fileFindingLocationData\":{\"startLine\":15, \"endLine\":15, \"startColumn\":26, \"endColumn\":46}}",
					},
					Desc:  ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
					Title: "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value",
				},
				Message: ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "terragoat/terraform/aws/ec2.tf",
									Path: ptr.Ptr("file://terragoat/terraform/aws/ec2.tf"),
								},
								StartLine: ptr.Ptr(int32(15)),
								EndLine:   ptr.Ptr(int32(15)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "798",
						},
						Desc:       ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
						VendorName: ptr.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://govwa/user/session/session.go\"}, \"fileFindingLocationData\":{\"startLine\":27, \"endLine\":31, \"startColumn\":20, \"endColumn\":3}}",
					},
					Desc:  ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
					Title: "go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly",
				},
				Message: ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "govwa/user/session/session.go",
									Path: ptr.Ptr("file://govwa/user/session/session.go"),
								},
								StartLine: ptr.Ptr(int32(27)),
								EndLine:   ptr.Ptr(int32(31)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "1004",
						},
						Desc:           ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
						FixAvailable:   ptr.Ptr(true),
						IsFixAvailable: ptr.Ptr(true),
						Severity:       ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:          ptr.Ptr("go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
						VendorName:     ptr.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"targetType\":\"TARGET_TYPE_REPOSITORY\", \"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\", \"path\":\"file://go-dvwa/vulnerable/system.go\"}, \"fileFindingLocationData\":{\"startLine\":9, \"endLine\":9, \"startColumn\":9, \"endColumn\":50}}",
					},
					Desc:  ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
					Title: "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
				},
				Message: ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "go-dvwa/vulnerable/system.go",
									Path: ptr.Ptr("file://go-dvwa/vulnerable/system.go"),
								},
								StartLine: ptr.Ptr(int32(9)),
								EndLine:   ptr.Ptr(int32(9)),
							},
						},
						Desc:       ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
						VendorName: ptr.Ptr("Semgrep OSS"),
					},
				},
			},
		}
		transformer, err := NewSarifTransformer(&sarifOutput, "", TargetTypeRepository, clock)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)

	})
	t.Run("trivy testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/trivy_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		now := time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:   ptr.Ptr(int64(1730419200)),
					CreatedTimeDt: timestamppb.New(now),
					DataSources: []string{
						"{\"uri\":{\"uriSchema\":\"URI_SCHEMA_PURL\", \"path\":\"pkg:docker/library/ubuntu\"}, \"fileFindingLocationData\":{\"startLine\":1, \"endLine\":1, \"startColumn\":1, \"endColumn\":1}}",
					},
					Desc:  ptr.Ptr("Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)"),
					Title: "Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)",
				},
				Message: ptr.Ptr("Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("CVE-2016-20013"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Trivy"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_UNKNOWN),
				Status:     ptr.Ptr("STATUS_ID_UNKNOWN"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
								EndLine:   ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "ubuntu",
								PackageManager: ptr.Ptr("docker"),
								Purl:           ptr.Ptr("pkg:docker/ubuntu"),
							}},
						Desc:       ptr.Ptr("Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)"),
						Severity:   ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
						Title:      ptr.Ptr("Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)"),
						VendorName: ptr.Ptr("Trivy"),
					},
				},
			},
		}
		transformer, err := NewSarifTransformer(&sarifOutput, "docker", TargetTypeImage, clock)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		for _, a := range actualIssues {
			b, _ := protojson.Marshal(a)
			fmt.Println(string(b))
		}
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)

	})
}
