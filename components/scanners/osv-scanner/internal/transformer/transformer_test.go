package transformer

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

// test that it finds both requirements.txt and pyproject.toml

func TestTransformer_Transform(t *testing.T) {
	var (
		clock = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
	)

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		t.Setenv("RAW_OUT_FILE", "./testdata/osv-scan-output.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/code")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 11)
	})
	t.Run("it should exit cleanly when there are no results", func(t *testing.T) {
		os.Setenv("RAW_OUT_FILE", "./testdata/empty.json")
		t.Setenv("WORKSPACE_PATH", "/code")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, nil, 0)
	})
	t.Run("it should return an error when there are malformed results", func(t *testing.T) {
		t.Setenv("RAW_OUT_FILE", "./testdata/malformed.json")
		t.Setenv("WORKSPACE_PATH", "/code")
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
		)
		require.NoError(t, err)
		transformMethodTest(t, ocsfTransformer.Transform, ErrMalformedSARIFfile, 0)
	})
	t.Run("it should extract the relative path from the absolute path", func(t *testing.T) {
		t.Setenv("RAW_OUT_FILE", "./testdata/osv-scan-single-output.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		var (
			ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
			clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
			nowUnix     = clock.Now().Unix()
			falseBool   = false
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
		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
		)
		require.NoError(t, err)

		expectedRelativePath := "sample/go.mod"

		expectedDataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprint("file://" + expectedRelativePath),
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
					Desc:          utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
					Title:         utils.Ptr("CVE-2025-22869: Potential denial of service in golang.org/x/crypto"),
					Severity:      utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
					FirstSeenTime: &nowUnix,
					LastSeenTime:  &nowUnix,
					Cwe:           nil,
					Cve: &ocsf.Cve{
						Uid:  "CVE-2025-22869",
						Desc: utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
					},
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Name: "sample/go.mod",
								Path: utils.Ptr("file://sample/go.mod"),
							},
						},
					},
					VendorName:      utils.Ptr("osv-scanner"),
					FirstSeenTimeDt: &timestamppb.Timestamp{Seconds: nowUnix},
					LastSeenTimeDt:  &timestamppb.Timestamp{Seconds: nowUnix},
					IsFixAvailable:  &falseBool,
					FixAvailable:    &falseBool,
				},
			},
		}

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 1)

		actualFinding := findings[0]
		require.JSONEq(t, string(expectedDataSourceJSON), actualFinding.FindingInfo.DataSources[0])
		require.Equal(t, expectedFinding.Vulnerabilities, actualFinding.Vulnerabilities)

	})
	t.Run("it should return an error, could not construct path for affected code", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		t.Setenv("RAW_OUT_FILE", "./testdata/osv-scan-single-output.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/some-random-path")

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

		ocsfTransformer, err := New(
			OSVScannerTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		require.ErrorContains(t, err, ErrConstructPath.Error())
		require.Nil(t, findings)
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
