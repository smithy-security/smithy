package transformer_test

import (
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/components/scanners/kics/internal/transformer"
)

func TestKicsTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		nowUnix     = clock.Now().Unix()
		typeUid     = int64(
			ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
				100 +
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		)
		falseBool = false
	)

	defer cancel()
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"
	targetMetadata := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)
	t.Setenv("KICS_WORKSPACE_PATH", "/code")

	ocsfTransformer, err := transformer.New(
		transformer.KicsRawOutFilePath("./testdata/kics-output.json.sarif"),
		transformer.KicsTransformerWithTarget(transformer.TargetTypeRepository),
		transformer.KicsTransformerWithClock(clock),
	)
	require.NoError(t, err)

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 3)

		for idx, finding := range findings {
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String(),
				*finding.ActivityName,
				"Unexpected activity name for finding %d", idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				finding.ActivityId,
				"Unexpected activity id for finding %d", idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				finding.CategoryUid,
				"Unexpected category uid for finding %d", idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				finding.ClassUid,
				"Unexpected category class uid for finding %d", idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String(),
				*finding.ClassName,
				"Unexpected category class name for finding %d", idx,
			)
			assert.Containsf(
				t,
				[]string{
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH.String(),
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM.String(),
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW.String(),
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN.String(),
				},
				*finding.Confidence,
				"Unexpected confidence name for finding %d", idx,
			)
			assert.Containsf(
				t,
				[]ocsf.VulnerabilityFinding_ConfidenceId{
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH,
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM,
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW,
					ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN,
				},
				*finding.ConfidenceId,
				"Unexpected confidence id for finding %d", idx,
			)
			// assert.NotNilf(t, finding.Count, "Unexpected count for finding %d", idx)
			assert.NotEmptyf(t, finding.Message, "Unexpected empty message for finding %d", idx)
			assert.Containsf(
				t,
				[]ocsf.VulnerabilityFinding_SeverityId{
					ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
					ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				},
				finding.SeverityId,
				"Unexpected severity id for finding %d", idx,
			)
			assert.Containsf(
				t,
				[]string{
					ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String(),
					ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
					ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String(),
				},
				*finding.Severity,
				"Unexpected severity for finding %d", idx,
			)
			// assert.Equalf(t, nowUnix, *finding.StartTime, "Unexpected start time for finding %d", idx)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_STATUS_ID_NEW.String(),
				*finding.Status,
				"Unexpected status for finding %d",
				idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_STATUS_ID_NEW,
				*finding.StatusId,
				"Unexpected status id for finding %d",
				idx,
			)
			assert.Equalf(t, nowUnix, finding.Time, "Unexpected time for finding %d", idx)
			assert.Equalf(t, typeUid, finding.TypeUid, "Unexpected type uid for finding %d", idx)
			require.NotNilf(t, finding.FindingInfo, "Unexpected nil finding info for finding %d", idx)
			findingInfo := finding.FindingInfo
			assert.Equalf(t, nowUnix, *findingInfo.CreatedTime, "Unexpected finding info created time for finding %d", idx)
			// assert.Equalf(t, nowUnix, *findingInfo.FirstSeenTime, "Unexpected finding info first time seen for finding %d", idx)
			// assert.Equalf(t, nowUnix, *findingInfo.LastSeenTime, "Unexpected finding info last time seen for finding %d", idx)
			// assert.Equalf(t, nowUnix, *findingInfo.ModifiedTime, "Unexpected finding info modified time seen for finding %d", idx)
			assert.NotEmptyf(t, *findingInfo.Desc, "Unexpected empty desc for finding %d", idx)
			assert.NotEmptyf(t, findingInfo.Title, "Unexpected empty title for finding %d", idx)
			assert.NotEmptyf(t, findingInfo.Uid, "Unexpected empty uid for finding %d", idx)

			var dataSource ocsffindinginfo.DataSource
			require.Lenf(
				t,
				findingInfo.DataSources,
				1, "Unexpected number of data sources for finding %d. Expected 1",
				idx,
			)
			require.NoErrorf(
				t,
				protojson.Unmarshal([]byte(findingInfo.DataSources[0]), &dataSource),
				"Unexpected error unmarshaling data source for finding %d",
				idx,
			)
			assert.Equalf(
				t,
				ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
				dataSource.TargetType,
				"Unexpected data source target type for finding %d",
				idx,
			)
			require.NotNilf(t, dataSource.Uri, "Unexpected nil data source uri for finding %d", idx)
			assert.Equalf(
				t,
				ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				dataSource.Uri.UriSchema,
				"Unexpected data source uri schema for finding %d",
				idx,
			)
			assert.NotEmptyf(t, dataSource.Uri.Path, "Unexpected empty data source path for finding %d", idx)
			require.NotNilf(t, dataSource.LocationData, "Unexpected nil data source location data for finding %d", idx)
			require.NotNilf(t, dataSource.SourceCodeMetadata, "Unexpected nil data source source code metadata for finding %d", idx)
			require.Lenf(t, finding.Vulnerabilities, 1, "Unexpected number of vulnerabilities for finding %d. Expected 1", idx)
			vulnerability := finding.Vulnerabilities[0]
			// assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			// assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.Containsf(
				t,
				[]string{
					ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String(),
					ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
					ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String(),
				},
				*vulnerability.Severity,
				"Unexpected severity for vulnerability for finding %d", idx,
			)
			assert.NotEmptyf(t, vulnerability.Title, "Unexpected empty title for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.Desc, "Unexpected empty desc for vulnerability for finding %d", idx)
			require.Lenf(t, vulnerability.AffectedCode, 1, "Unexpected lenght for affected code for vulnerability for finding %d. Expected 1", idx)

			var affectedCode = vulnerability.AffectedCode[0]
			require.NotNilf(t, affectedCode.File, "Unexpected nil file for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, affectedCode.File.Path, "Unexpected empty file path for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, affectedCode.File.Name, "Unexpected empty file name for vulnerability for finding %d", idx)
			assert.NotNilf(t, affectedCode.StartLine, "Unexpected nil start line for vulnerability for finding %d", idx)
		}
	})

	t.Run("it should extract the relative path from the absolute path", func(t *testing.T) {
		expectedRelativePath := "KaiMonkey/cft/dms/replication-instance/deploy.yml"

		expectedDataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprint("file://" + expectedRelativePath),
			},

			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine: 13,
				},
			},
			SourceCodeMetadata: targetMetadata.SourceCodeMetadata,
		}

		expectedDataSourceJSON, err := protojson.Marshal(expectedDataSource)
		require.NoError(t, err)

		expectedFinding := &ocsf.VulnerabilityFinding{
			FindingInfo: &ocsf.FindingInfo{
				DataSources: []string{string(expectedDataSourceJSON)},
			},
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					Desc:          utils.Ptr("Amazon DMS is publicly accessible, therefore exposing possible sensitive information. To prevent such a scenario, update the attribute 'PubliclyAccessible' to false.\n\n More info: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html"),
					Title:         utils.Ptr("Amazon DMS Replication Instance Is Publicly Accessible"),
					Severity:      utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
					FirstSeenTime: &nowUnix,
					LastSeenTime:  &nowUnix,

					Cwe: &ocsf.Cwe{
						Uid:     "284",
						SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/284.html"),
						Caption: utils.Ptr("Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Accountability (tracking of activities that were performed) When any mechanism is not applied or otherwise fails, attackers can compromise the security of the product by gaining privileges, reading sensitive information, executing commands, evading detection, etc. There are two distinct behaviors that can introduce access control weaknesses: Specification: incorrect privileges, permissions, ownership, etc. are explicitly specified for either the user or the resource (for example, setting a password file to be world-writable, or giving administrator capabilities to a guest user). This action could be performed by the program or the administrator. Enforcement: the mechanism contains errors that prevent it from properly enforcing the specified access control requirements (e.g., allowing the user to specify their own privileges, or allowing a syntactically-incorrect ACL to produce insecure settings). This problem occurs within the program itself, in that it does not actually enforce the intended security policy that the administrator specifies."),
					},
					Cve: nil,
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Name: "KaiMonkey/cft/dms/replication-instance/deploy.yml",
								Path: utils.Ptr("file://KaiMonkey/cft/dms/replication-instance/deploy.yml"),
							},
							StartLine: utils.Ptr(int32(13)),
						},
					},
					VendorName:      utils.Ptr("KICS"),
					FirstSeenTimeDt: &timestamppb.Timestamp{Seconds: nowUnix},
					LastSeenTimeDt:  &timestamppb.Timestamp{Seconds: nowUnix},
					IsFixAvailable:  &falseBool,
					FixAvailable:    &falseBool,
				},
			},
		}

		ocsfTransformer, err := transformer.New(
			transformer.KicsRawOutFilePath("./testdata/kics.valid.sarif"),
			transformer.KicsTransformerWithTarget(transformer.TargetTypeRepository),
			transformer.KicsTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 1)

		actualFinding := findings[0]
		require.JSONEq(t, string(expectedDataSourceJSON), actualFinding.FindingInfo.DataSources[0])
		require.Equal(t, expectedFinding.Vulnerabilities, actualFinding.Vulnerabilities)

	})

	t.Run("it should not return an error if the results file is a valid empty sarif json", func(t *testing.T) {
		ocsfTransformer, err := transformer.New(
			transformer.KicsRawOutFilePath("./testdata/kics.empty.valid.sarif"),
			transformer.KicsTransformerWithTarget(transformer.TargetTypeRepository),
			transformer.KicsTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should return an error if the results file doesn't exit", func(t *testing.T) {
		ocsfTransformer, err := transformer.New(
			transformer.KicsRawOutFilePath("./testdata/non.existent.sarif"),
			transformer.KicsTransformerWithTarget(transformer.TargetTypeRepository),
			transformer.KicsTransformerWithClock(clock),
		)
		require.NoError(t, err)

		_, err = ocsfTransformer.Transform(ctx)
		require.Error(t, err)
	})
}
