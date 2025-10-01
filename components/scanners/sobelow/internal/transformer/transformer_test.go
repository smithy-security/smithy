package transformer_test

import (
	"context"
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

	"github.com/smithy-security/smithy/components/scanners/sobelow/internal/transformer"
)

func TestSobelowTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
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

	t.Run("it should transform correctly the finding to ocsf format", func(t *testing.T) {
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		expectedRelativePath := "lib/carafe_web/controllers/potion_controller.ex"

		expectedDataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprint("file://" + expectedRelativePath),
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   43,
					StartColumn: 32,
					EndColumn:   32,
					EndLine:     43,
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
					Desc:          utils.Ptr("CI.System: Command Injection via `System` function\n\n Help: # Command Injection via `System`\n\nThis submodule of the `CI` module checks for Command Injection vulnerabilities through usage of the `System.cmd` function.\n\nEnsure the the command passed to `System.cmd` is not user-controlled.\n\n`System.cmd` Injection checks can be ignored with the following command:\n\n    $ mix sobelow -i CI.System "),
					Title:         utils.Ptr("Command Injection via `System` function"),
					Severity:      utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
					FirstSeenTime: &nowUnix,
					LastSeenTime:  &nowUnix,
					Cwe:           nil,
					Cve:           nil,
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Name: "lib/carafe_web/controllers/potion_controller.ex",
								Path: utils.Ptr("file://lib/carafe_web/controllers/potion_controller.ex"),
							},
							StartLine: utils.Ptr(int32(43)),
							EndLine:   utils.Ptr(int32(43)),
						},
					},
					VendorName:      utils.Ptr("Sobelow"),
					FirstSeenTimeDt: &timestamppb.Timestamp{Seconds: nowUnix},
					LastSeenTimeDt:  &timestamppb.Timestamp{Seconds: nowUnix},
					IsFixAvailable:  &falseBool,
					FixAvailable:    &falseBool,
				},
			},
		}

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath("./testdata/single-file-sarif"),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Len(t, findings, 2)

		actualFinding := findings[0]
		require.JSONEq(t, string(expectedDataSourceJSON), actualFinding.FindingInfo.DataSources[0])
		require.Equal(t, expectedFinding.Vulnerabilities, actualFinding.Vulnerabilities)
	})

	t.Run("it should merge and transform findings from multiple files in a directory", func(t *testing.T) {
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		expectedRelativePath := "sarif1/lib/carafe_web/controllers/potion_controller.ex"

		expectedDataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprint("file://" + expectedRelativePath),
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   43,
					StartColumn: 32,
					EndColumn:   32,
					EndLine:     43,
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
					Desc:          utils.Ptr("CI.System: Command Injection via `System` function\n\n Help: # Command Injection via `System`\n\nThis submodule of the `CI` module checks for Command Injection vulnerabilities through usage of the `System.cmd` function.\n\nEnsure the the command passed to `System.cmd` is not user-controlled.\n\n`System.cmd` Injection checks can be ignored with the following command:\n\n    $ mix sobelow -i CI.System "),
					Title:         utils.Ptr("Command Injection via `System` function"),
					Severity:      utils.Ptr(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
					FirstSeenTime: &nowUnix,
					LastSeenTime:  &nowUnix,
					Cwe:           nil,
					Cve:           nil,
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Name: "sarif1/lib/carafe_web/controllers/potion_controller.ex",
								Path: utils.Ptr("file://sarif1/lib/carafe_web/controllers/potion_controller.ex"),
							},
							StartLine: utils.Ptr(int32(43)),
							EndLine:   utils.Ptr(int32(43)),
						},
					},
					VendorName:      utils.Ptr("Sobelow"),
					FirstSeenTimeDt: &timestamppb.Timestamp{Seconds: nowUnix},
					LastSeenTimeDt:  &timestamppb.Timestamp{Seconds: nowUnix},
					IsFixAvailable:  &falseBool,
					FixAvailable:    &falseBool,
				},
			},
		}

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath("./testdata/multiple-sarif-files"),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		// Each file has 2 findings, so 2 files should result in 4 findings.
		require.Len(t, findings, 4)

		actualFinding := findings[2]
		require.JSONEq(t, string(expectedDataSourceJSON), actualFinding.FindingInfo.DataSources[0])
		require.Equal(t, expectedFinding.Vulnerabilities, actualFinding.Vulnerabilities)
	})

	t.Run("it should not return an error if the directory contains a valid but empty sarif json", func(t *testing.T) {
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath("./testdata/empty-valid-sarif-file"),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should not return an error if the directory contains a complete (invalid) empty file", func(t *testing.T) {
		// We are treating complete empty sarif.json file as no findings to report
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath("./testdata/empty-sarif-file"),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should not return an error for empty results directory", func(t *testing.T) {
		emptyDir := t.TempDir() // Creates a temporary, empty directory for the test.
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath(emptyDir),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should return an error if the results file doesn't exit", func(t *testing.T) {
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
			transformer.SobelowResultsDirPath("./testdata/non-existent-dir"),
		)
		require.NoError(t, err)

		_, err = ocsfTransformer.Transform(ctx)
		require.Error(t, err)
	})

}
