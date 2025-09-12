package transformer

import (
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func TestTrufflehogTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		nowUnix     = clock.Now().Unix()
		typeUID     = int64(
			ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
				100 +
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		)
	)

	defer cancel()
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"
	targetMetadata := &ocsffindinginfo.DataSource{
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)
	t.Setenv("TRUFFLEHOG_SOURCE_CODE_WORKSPACE", "/pwd")
	ocsfTransformer, err := New(
		TrufflehogRawOutFilePath("./testdata/trufflehog.json"),
		TrufflehogTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
		TrufflehogTransformerWithClock(clock),
	)
	require.NoError(t, err)

	t.Run("it should transform the finding to a valid ocsf message", func(t *testing.T) {
		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 78)

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
				},
				*finding.ConfidenceId,
				"Unexpected confidence id for finding %d", idx,
			)
			assert.NotNilf(t, finding.Count, "Unexpected count for finding %d", idx)
			assert.NotEmptyf(t, finding.Message, "Unexpected empty message for finding %d", idx)
			assert.Equalf(
				t, ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH, finding.SeverityId,
				"Unexpected severity id for finding %d", idx,
			)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
				*finding.Severity,
				"Unexpected severity for finding %d", idx,
			)
			assert.Equalf(t, nowUnix, *finding.StartTime, "Unexpected start time for finding %d", idx)
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
			assert.Equalf(t, typeUID, finding.TypeUid, "Unexpected type uid for finding %d", idx)
			require.NotNilf(t, finding.FindingInfo, "Unexpected nil finding info for finding %d", idx)
			findingInfo := finding.FindingInfo
			assert.Equalf(t, nowUnix, *findingInfo.CreatedTime, "Unexpected finding info created time for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.FirstSeenTime, "Unexpected finding info first time seen for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.LastSeenTime, "Unexpected finding info last time seen for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.ModifiedTime, "Unexpected finding info modified time seen for finding %d", idx)
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
			assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.Equalf(
				t,
				ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
				*vulnerability.Severity,
				"Unexpected severity for vulnerability for finding %d", idx,
			)
			assert.NotEmptyf(t, vulnerability.Title, "Unexpected empty title for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.Desc, "Unexpected empty desc for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.VendorName, "Unexpected empty name of tool for finding %d", idx)
			require.Lenf(t, vulnerability.AffectedCode, 1, "Unexpected length for affected code for vulnerability for finding %d. Expected 1", idx)

			var affectedCode = vulnerability.AffectedCode[0]
			require.NotNilf(t, affectedCode.File, "Unexpected nil file for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, affectedCode.File.Path, "Unexpected empty file path for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, affectedCode.File.Name, "Unexpected empty file name for vulnerability for finding %d", idx)
			assert.NotNilf(t, affectedCode.StartLine, "Unexpected nil start line for vulnerability for finding %d", idx)

			require.NotNilf(t, vulnerability.Cwe, "Unexpected nil cwe for vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.Cwe.SrcUrl, "Unexpected empty value for src url in vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.Cwe.Uid, "Unexpected empty value for uid in vulnerability for finding %d", idx)
			assert.NotEmptyf(t, vulnerability.Cwe.Caption, "Unexpected empty value for caption in vulnerability for finding %d", idx)
		}
	})
	t.Run("it should extract the relative path from the absolute path", func(t *testing.T) {
		t.Setenv("TRUFFLEHOG_SOURCE_CODE_WORKSPACE", "/pwd")
		transformer, err := New(
			TrufflehogRawOutFilePath("./testdata/trufflehog_matching_path.json"),
			TrufflehogTransformerWithClock(clock),
			TrufflehogTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
		)
		require.NoError(t, err)

		expectedRelativePath := ".git/objects/06/a26a7f8c8e7dd7e07594f5c061f397b05ffbfe"

		// Check the path for the dataSource
		expectedDataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprint("file://" + expectedRelativePath),
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine: 2,
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
					Desc:          utils.Ptr("Trufflehog found hardcoded credentials (Redacted):\n"),
					Title:         utils.Ptr("trufflehog - filesystem\nPLAIN:Box"),
					Severity:      utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
					FirstSeenTime: &nowUnix,
					LastSeenTime:  &nowUnix,
					Cwe: &ocsf.Cwe{
						Uid:     "798",
						Caption: utils.Ptr("Use of Hard-coded Credentials"),
						SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/798.html"),
					},
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Name: "a26a7f8c8e7dd7e07594f5c061f397b05ffbfe",
								Path: utils.Ptr("file://" + expectedRelativePath),
							},
							StartLine: utils.Ptr(int32(2)),
						},
					},
					VendorName: utils.Ptr("trufflehog"),
				},
			},
		}

		findings, err := transformer.Transform(ctx)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		actualFinding := findings[0]
		require.Equal(t, expectedFinding.Vulnerabilities, actualFinding.Vulnerabilities)
		require.JSONEq(t, string(expectedDataSourceJSON), actualFinding.FindingInfo.DataSources[0])

	})
	t.Run("it should return an error", func(t *testing.T) {
		// set the prefix to a value that is not a prefix in the findings' SourceMetadata.file field
		t.Setenv("TRUFFLEHOG_SOURCE_CODE_WORKSPACE", "/workspace/source-code")

		transformer, err := New(
			TrufflehogRawOutFilePath("./testdata/trufflehog_mismatching_path.json"),
			TrufflehogTransformerWithClock(clock),
			TrufflehogTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
		)
		require.NoError(t, err)

		findings, err := transformer.Transform(ctx)
		require.Error(t, err)
		require.Nil(t, findings)
		require.ErrorIs(t, err, ErrPrefixNotInPath)
	})
}
