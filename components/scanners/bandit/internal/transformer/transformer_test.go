package transformer

import (
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"context"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func fakeClock() clockwork.FakeClock {
	return *clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
}

func TestBanditTransformer_Transform(t *testing.T) {
	clock := fakeClock()

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		os.Setenv("BANDIT_RAW_OUT_FILE_PATH", "./testdata/bandit.json")
		ocsfTransformer, err := New(
			BanditTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
			BanditTransformerWithClock(&clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 10)
	})

	t.Run("it should error for findings without a line range", func(t *testing.T) {
		os.Setenv("BANDIT_RAW_OUT_FILE_PATH", "./testdata/bandit.json")
		ocsfTransformer, err := New(
			BanditTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
			BanditTransformerWithClock(&clock),
			BanditRawOutFileContents([]byte(noLineRangeInput)),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, ErrNoLineRange, 0)
	})

	t.Run("it should error for findings with an invalid data source", func(t *testing.T) {
		os.Setenv("BANDIT_RAW_OUT_FILE_PATH", "./testdata/bandit.json")
		ocsfTransformer, err := New(
			BanditTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
			BanditTransformerWithClock(&clock),
			BanditRawOutFileContents([]byte(noDataSourceInput)),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, ErrBadDataSource, 0)
	})
	t.Run("it should not error when receiving an empty inFile", func(t *testing.T) {
		emptyFilePath := filepath.Join(t.TempDir(), "empty.sarif")
		os.Setenv("BANDIT_RAW_OUT_FILE_PATH", emptyFilePath)
		require.NoError(t, os.WriteFile(os.Getenv("BANDIT_RAW_OUT_FILE_PATH"), []byte("{}"), 0644))
		ocsfTransformer, err := New(
			BanditTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
			BanditTransformerWithClock(&clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 0)
	})
	t.Run("it should error when receiving a non existing inFile", func(t *testing.T) {
		os.Setenv("BANDIT_RAW_OUT_FILE_PATH", "./testdata/foobar.json")
		ocsfTransformer, err := New(
			BanditTransformerWithTarget(ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY),
			BanditTransformerWithClock(&clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, ErrFileNotFound, 0)
	})
}

func assertValid(t *testing.T, finding *ocsf.VulnerabilityFinding, idx int, nowUnix, typeUID int64) {
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
	assert.Containsf(
		t,
		[]ocsf.VulnerabilityFinding_SeverityId{
			ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
			ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
			ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
			ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
		},
		finding.SeverityId,
		"Unexpected severity id %s for finding %d", finding.SeverityId, idx,
	)
	assert.Containsf(
		t,
		[]string{
			ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String(),
			ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
			ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String(),
			ocsf.VulnerabilityFinding_SEVERITY_ID_LOW.String(),
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
	require.NotNilf(t, dataSource.SourceCodeMetadata, "Unexpected nil data sourcecode metadata for finding %d", idx)

	require.Lenf(t, finding.Vulnerabilities, 1, "Unexpected number of vulnerabilities for finding %d. Expected 1", idx)
	vulnerability := finding.Vulnerabilities[0]
	assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
	assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firsy time seen time for finding %d", idx)
	assert.Containsf(
		t,
		[]string{
			ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String(),
			ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(),
			ocsf.VulnerabilityFinding_SEVERITY_ID_LOW.String(),
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

	require.NotNilf(t, vulnerability.Cwe, "Unexpected nil cwe for vulnerability for finding %d", idx)
	assert.NotEmptyf(t, vulnerability.Cwe.SrcUrl, "Unexpected empty value for src url in vulnerability for finding %d", idx)
	assert.NotEmptyf(t, vulnerability.Cwe.Uid, "Unexpected empty value for uid in vulnerability for finding %d", idx)
}

func transformMethodTest(t *testing.T, transformCallback func(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error), expectedError error, expectedFindingsLength int) {
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
	commitRef := "fb00c88b58a57ce73de1871c3b51776386d603fa"
	repositoryURL := "https://github.com/smithy-security/test"
	targetMetadata := &ocsffindinginfo.DataSource{
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

	defer cancel()
	findings, err := transformCallback(ctx)
	if expectedError != nil {
		require.ErrorIsf(t, err, expectedError, "did not receive the expected error, got %w, wanted %w", err, expectedError)
		return
	}
	require.NoError(t, err)
	require.Equal(t, expectedFindingsLength, len(findings))

	for idx, finding := range findings {
		assertValid(t, finding, idx, nowUnix, typeUID)
	}
}

var (
	noLineRangeInput = `{
  "errors": [],
  "generated_at": "2023-12-28T13:07:40Z",
  "results": [
    {
      "code": "24     req = urllib.request.Request(url, headers={\"User-Agent\": \"Magic Browser\"})\n25     image = urllib.request.urlopen(req).read()\n26 \n",
      "col_offset": 12,
      "end_col_offset": 39,
      "filename": "/code/AWSGoat/modules/module-1/resources/lambda/data/lambda_function.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 22,
        "link": "https://cwe.mitre.org/data/definitions/22.html"
      },
      "issue_severity": "MEDIUM",
      "issue_text": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
      "line_number": 25,
      "line_range": [],
      "more_info": "https://bandit.readthedocs.io/en/1.7.5/blacklists/blacklist_calls.html#b310-urllib-urlopen",
      "test_id": "B310",
      "test_name": "blacklist"
    }
  ]
}`
	noDataSourceInput = `{
  "errors": [],
  "generated_at": "2023-12-28T13:07:40Z",
  "results": [
    {
      "code": "24     req = urllib.request.Request(url, headers={\"User-Agent\": \"Magic Browser\"})\n25     image = urllib.request.urlopen(req).read()\n26 \n",
      "col_offset": 12,
      "end_col_offset": 39,
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 22,
        "link": "https://cwe.mitre.org/data/definitions/22.html"
      },
      "issue_severity": "MEDIUM",
      "issue_text": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
      "line_number": 25,
      "line_range": [
        25
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.5/blacklists/blacklist_calls.html#b310-urllib-urlopen",
      "test_id": "B310",
      "test_name": "blacklist"
    }
  ]
}`
)
