package transformer_test

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/components/scanners/trivy/internal/transformer"
)

func TestTrivyTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		nowUnix     = clock.Now().Unix()
		typeUid     = int64(
			ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
				100 +
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		)
	)
	defer cancel()
	targetMetadata := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
		OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
			PackageUrl: "pkg:docker/example/myapp@1.0",
			Tag:        "1.0",
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

	ocsfTransformer, err := transformer.New(
		transformer.TrivyRawOutFilePath("./testdata/trivy.sarif.json"),
		transformer.TrivyTransformerWithTarget(transformer.TargetTypeContainer),
		transformer.TrivyTransformerWithClock(clock),
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
			assert.NotNilf(t, finding.Count, "Unexpected count for finding %d", idx)
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
			assert.Equalf(t, typeUid, finding.TypeUid, "Unexpected type uid for finding %d", idx)
			require.NotNilf(t, finding.FindingInfo, "Unexpected nil finding info for finding %d", idx)
			findingInfo := finding.FindingInfo
			assert.Equalf(t, nowUnix, *findingInfo.CreatedTime, "Unexpected finding info created time for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.FirstSeenTime, "Unexpected finding info first time seen for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.LastSeenTime, "Unexpected finding info last time seen for finding %d", idx)
			assert.Equalf(t, nowUnix, *findingInfo.ModifiedTime, "Unexpected finding info modified time seen for finding %d", idx)
			assert.NotEmptyf(t, *findingInfo.Desc, "Unexpected empty desc for finding %d", idx)
			assert.NotEmptyf(t, findingInfo.Title, "Unexpected empty title for finding %d", idx)
			assert.NotEmptyf(t, findingInfo.Uid, "Unexpected empty uid for finding %d", idx)
			assert.Equalf(t, "Trivy", *findingInfo.ProductUid, "Unexpected findingInfo.ProductUid for finding %d", idx)

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
				ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
				dataSource.TargetType,
				"Unexpected data source target type for finding %d",
				idx,
			)
			// require.NotNilf(t, dataSource.Uri, "Unexpected nil data source uri for finding %d", idx)
			assert.Equalf(
				t,
				ocsffindinginfo.DataSource_URI_SCHEMA_PURL,
				dataSource.Uri.UriSchema,
				"Unexpected data source uri schema for finding %d",
				idx,
			)
			assert.NotEmptyf(t, dataSource.Uri.Path, "Unexpected empty data source path for finding %d", idx)
			require.NotNilf(t, dataSource.LocationData, "Unexpected nil data source location data for finding %d", idx)
			require.NotNilf(t, dataSource.OciPackageMetadata, "Unexpected nil data source OCI PACKAGE METADATA %d", idx)

			require.Lenf(t, finding.Vulnerabilities, 1, "Unexpected number of vulnerabilities for finding %d. Expected 1", idx)
			vulnerability := finding.Vulnerabilities[0]
			assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.NotEmpty(t, vulnerability.Cve.Uid)
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
			assert.NotNilf(t, affectedCode.EndLine, "Unexpected nil end line for vulnerability for finding %d", idx)
		}
	})
	t.Run("it should return an empty finding array when the input file is empty", func(t *testing.T) {
		emptyFilePath := filepath.Join(t.TempDir(), "empty.sarif.json")
		require.NoError(t, os.WriteFile(emptyFilePath, []byte{}, 0644))

		ocsfTransformer, err := transformer.New(
			transformer.TrivyRawOutFilePath(emptyFilePath),
			transformer.TrivyTransformerWithTarget(transformer.TargetTypeContainer),
			transformer.TrivyTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		assert.Empty(t, findings, "Expected no findings for an empty input file")
	})
}
