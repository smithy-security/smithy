package transformer

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
)

func fakeClock() *clockwork.FakeClock {
	return clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
}

// test that it finds both requirements.txt and pyproject.toml

func TestTransformer_Transform(t *testing.T) {
	var (
		clock = fakeClock()
	)

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		path, err := os.Getwd()
		require.NoError(t, err)
		os.Setenv("RAW_OUT_FILE", "./testdata/osv-scan-output.sarif.json")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
			OSVScannerTransformerWithProjectRoot(filepath.Join(path, ".")),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 11)
	})
	t.Run("it should exit cleanly when there are no results", func(t *testing.T) {
		path, err := os.Getwd()
		require.NoError(t, err)
		os.Setenv("RAW_OUT_FILE", "./testdata/empty.json")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
			OSVScannerTransformerWithProjectRoot(filepath.Join(path, ".")),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 0)
	})
	t.Run("it should return an error when there are malformed results", func(t *testing.T) {
		path, err := os.Getwd()
		require.NoError(t, err)
		os.Setenv("RAW_OUT_FILE", "./testdata/malformed.json")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
			OSVScannerTransformerWithProjectRoot(filepath.Join(path, ".")),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, ErrMalformedSARIFfile, 0)
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
	assert.NotNilf(t, finding.Count, "Unexpected count for finding %d", idx)
	assert.NotEmptyf(t, finding.Message, "Unexpected empty message for finding %d", idx)
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
	require.NotNilf(t, dataSource.SourceCodeMetadata, "Unexpected nil data source source code metadata for finding %d", idx)

	require.Lenf(t, finding.Vulnerabilities, 1, "Unexpected number of vulnerabilities for finding %d. Expected 1", idx)
	vulnerability := finding.Vulnerabilities[0]
	assert.Equalf(t, nowUnix, *vulnerability.FirstSeenTime, "Unexpected vulnerability firstly time seen time for finding %d", idx)
	assert.Equalf(t, nowUnix, *vulnerability.LastSeenTime, "Unexpected vulnerability firstly time seen time for finding %d", idx)
	assert.NotEmptyf(t, vulnerability.Title, "Unexpected empty title for vulnerability for finding %d", idx)
	assert.NotEmptyf(t, vulnerability.Desc, "Unexpected empty desc for vulnerability for finding %d", idx)
	require.Lenf(t, vulnerability.AffectedCode, 1, "Unexpected length for affected code for vulnerability for finding %d. Expected 3", idx)

	var affectedCode = vulnerability.AffectedCode[0]
	require.NotNilf(t, affectedCode.File, "Unexpected nil file for vulnerability for finding %d", idx)
	assert.NotEmptyf(t, affectedCode.File.Path, "Unexpected empty file path for vulnerability for finding %d", idx)
	assert.NotEmptyf(t, affectedCode.File.Name, "Unexpected empty file name for vulnerability for finding %d", idx)
}

func transformMethodTest(t *testing.T,
	transformCallback func(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error),
	expectedError error,
	expectedNumFindings int) {
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
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: repositoryURL,
			Reference:     commitRef,
		},
	}

	ctx = context.WithValue(ctx, component.SCANNER_TARGET_METADATA_CTX_KEY, targetMetadata)

	findings, err := transformCallback(ctx)
	if expectedError != nil {
		require.ErrorIsf(t, err, expectedError, "did not receive the expected error, got %w, wanted %w", err, expectedError)
		return
	}
	require.NoError(t, err)
	require.Equal(t, expectedNumFindings, len(findings))
	for idx, finding := range findings {
		assertValid(t, finding, idx, nowUnix, typeUID)
	}
}
