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
		t.Setenv("SOBELOW_RAW_OUT_FILE_PATH", "./testdata/sobelow.sarif.json")
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

	t.Run("it should not return an error if the results file is a valid empty sarif", func(t *testing.T) {
		t.Setenv("SOBELOW_RAW_OUT_FILE_PATH", "./testdata/sobelow.empty.valid.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should not return an error if the results file is completely empty", func(t *testing.T) {
		t.Setenv("SOBELOW_RAW_OUT_FILE_PATH", "./testdata/sobelow.empty.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should return an error if the results file doesn't exit", func(t *testing.T) {
		t.Setenv("CREDO_RAW_OUT_FILE_PATH", "./testdata/sobelow.non.existent.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.SobelowTransformerWithClock(clock),
		)
		require.NoError(t, err)

		_, err = ocsfTransformer.Transform(ctx)
		require.Error(t, err)
	})

}
