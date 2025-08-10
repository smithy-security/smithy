package transformer_test

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/scanners/zaproxy/internal/transformer"
)

func TestZapTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		nowUnix     = clock.Now().Unix()
		typeUid     = int64(
			ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
				100 +
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		)
	)

	defer cancel()

	ocsfTransformer, err := transformer.New(
		transformer.ZapRawOutFilePath("./testdata/zap.sarif.json"),
		transformer.ZapTransformerWithTarget(transformer.TargetTypeWebsite),
		transformer.ZapTransformerWithClock(clock),
	)
	require.NoError(t, err)

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		target := "http://bodgeit.com:8080"
		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE,
			WebsiteMetadata: &ocsffindinginfo.DataSource_WebsiteMetadata{
				Url: target,
			},
		}

		ctx := context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, dataSource)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 3)
		expectedResultGUIDs := []string{
			"40012",
			"40012",
			"40018",
		}
		expectedMetadataUIDs := []string{
			"d12d62ce-a615-527c-8e13-e79655e31a7d",
			"be3749a7-3e6f-512c-9cd6-f6fd40dea190",
			"cf72f5da-0b15-5607-9da9-73175addad99",
		}
		expectedPaths := []string{
			"/bodgeit/search.jsp?q=%3C%2Ffont%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cfont%3E",
			"/bodgeit/contact.jsp",
			"/bodgeit/basket.jsp",
		}

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
			assert.Equal(t, expectedResultGUIDs[idx], findingInfo.Uid, "Unexpected uid for finding %d", idx)

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
				ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE,
				dataSource.TargetType,
				"Unexpected data source target type for finding %d",
				idx,
			)
			require.NotNil(t, dataSource.WebsiteMetadata)
			assert.Equal(t, target, dataSource.WebsiteMetadata.Url)
			require.NotNilf(t, dataSource.Uri, "Unexpected nil data source uri for finding %d", idx)
			assert.Equalf(
				t,
				ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
				dataSource.Uri.UriSchema,
				"Unexpected data source uri schema for finding %d",
				idx,
			)
			assert.NotEmptyf(t, dataSource.Uri.Path, "Unexpected empty data source path for finding %d", idx)
			require.NotNilf(t, dataSource.LocationData, "Unexpected nil data source location data for finding %d", idx)
			assert.Equal(t, expectedPaths[idx], dataSource.Uri.Path)

			require.Lenf(t, finding.Vulnerabilities, 1, "Unexpected number of vulnerabilities for finding %d. Expected 1", idx)
			vulnerability := finding.Vulnerabilities[0]
			assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
			assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firsy time	 seen time for finding %d", idx)
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
			require.Nilf(t, vulnerability.AffectedCode, "Unexpected NON nil file for web vulnerability for finding %d", idx)
			require.Nilf(t, vulnerability.AffectedPackages, "Unexpected NON nil file for web vulnerability for finding %d", idx)

			require.NotNil(t, finding.Metadata, "finding metadata are nil")
			assert.Equal(t, expectedMetadataUIDs[idx], *finding.Metadata.Uid, "Unexpected metadata uid for finding %d", idx)
		}
	})
}
func TestZapTransformer_Metrics(t *testing.T) {
	clock := clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
	ocsfTransformer, err := transformer.New(
		transformer.ZapRawOutFilePath("./testdata/zap.sarif.json"),
		transformer.ZapTransformerWithTarget(transformer.TargetTypeWebsite),
		transformer.ZapTransformerWithClock(clock),
	)
	require.NoError(t, err)

	b, err := ocsfTransformer.ReadFile("./testdata/zap.sarif.json")
	require.NoError(t, err)
	require.NotEmpty(t, b)

	var report sarifschemav210.SchemaJson
	require.NoError(t, report.UnmarshalJSON(b))
	metrics := ocsfTransformer.Metrics(context.Background(), &report)
	assert.NotEmpty(t, metrics)
	assert.Contains(t, metrics, "zap-transformer:\nruns=1\nresults=3")
	assert.Contains(t, metrics, "Paths=[http://bodgeit.com:8080")
	assert.Contains(t, metrics, "RuleIDs=[")
	assert.Contains(t, metrics, "40012")
	assert.Contains(t, metrics, "40018")
}

func TestZapTransformer_ReadFile_NotFound(t *testing.T) {
	tr, err := transformer.New(transformer.ZapRawOutFilePath("./testdata/nonexistent.json"))
	require.NoError(t, err)
	_, err = tr.ReadFile("./testdata/nonexistent.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
