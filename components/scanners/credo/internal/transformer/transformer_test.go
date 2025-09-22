package transformer_test

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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/components/scanners/credo/internal/transformer"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func TestTransformer_Transform(t *testing.T) {
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
	t.Run("it should extract the relative path from the absolute path", func(t *testing.T) {
		t.Setenv("CREDO_RAW_OUT_FILE_PATH", "./testdata/credo.sarif.json")
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
					StartLine:   44,
					StartColumn: 5,
					EndColumn:   15,
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
					Desc:          utils.Ptr("While calls to IO.inspect might appear in some parts of production code...\n\n More info: https://hexdocs.pm/credo/Credo.Check.Warning.IoInspect.html"),
					Title:         utils.Ptr("Credo.Check.Warning.IoInspect"),
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
							StartLine: utils.Ptr(int32(44)),
						},
					},
					VendorName:      utils.Ptr("Credo"),
					FirstSeenTimeDt: &timestamppb.Timestamp{Seconds: nowUnix},
					LastSeenTimeDt:  &timestamppb.Timestamp{Seconds: nowUnix},
					IsFixAvailable:  &falseBool,
					FixAvailable:    &falseBool,
				},
			},
		}

		ocsfTransformer, err := transformer.New(
			transformer.CredoTransformerWithClock(clock),
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

	t.Run("it should not return an error if the results file is empty", func(t *testing.T) {
		t.Setenv("CREDO_RAW_OUT_FILE_PATH", "./testdata/credo.empty.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.CredoTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		require.Empty(t, findings)
	})

	t.Run("it should return an error if the results file doesn't exit", func(t *testing.T) {
		t.Setenv("CREDO_RAW_OUT_FILE_PATH", "./testdata/credo.non.existent.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.CredoTransformerWithClock(clock),
		)
		require.NoError(t, err)

		_, err = ocsfTransformer.Transform(ctx)
		require.Error(t, err)
	})
}
