package transformer_test

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/scanners/credo/internal/transformer"
)

func TestTransformer_Transform(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		// nowUnix     = clock.Now().Unix()
		// typeUid     = int64(
		// 	ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
		// 		100 +
		// 		ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		// )
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

	t.Run("it should not return an error if the results file is empty", func(t *testing.T) {
		t.Setenv("RAW_OUT_FILE", "./testdata/credo.empty.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.CredoTransformerWithClock(clock),
		)
		require.NoError(t, err)

		findings, err := ocsfTransformer.Transform(ctx)
		assert.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("it should return an error if the results file doesn't exit", func(t *testing.T) {
		t.Setenv("RAW_OUT_FILE", "./testdata/credo.non.existent.sarif.json")
		t.Setenv("WORKSPACE_PATH", "/workspace/source-code")

		ocsfTransformer, err := transformer.New(
			transformer.CredoTransformerWithClock(clock),
		)
		require.NoError(t, err)

		_, err = ocsfTransformer.Transform(ctx)
		require.Error(t, err)
	})
}
