package transformer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/smithy-security/smithy/sdk/component"
	smithytesting "github.com/smithy-security/smithy/sdk/component/utils/testing"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/transformer/testdata"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/transformer/testdata/elixir"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/transformer/testdata/golang"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/internal/transformer/testdata/javascript"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
)

func TestOSVResultParser(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	testCtx = context.WithValue(
		testCtx,
		component.SCANNER_TARGET_METADATA_CTX_KEY,
		testdata.TargetMetadata,
	)

	t.Run("parse go results", func(t *testing.T) {
		// temporarily copy test.go.mod to go.mod to prevent the go tooling
		// and IDEs from tripping hard
		sourceFile, err := os.Open("./testdata/golang/test.go.mod")
		require.NoError(t, err)
		t.Cleanup(func() { sourceFile.Close() })

		destinationFile, err := os.Create("./testdata/golang/go.mod")
		require.NoError(t, err)
		t.Cleanup(func() {
			destinationFile.Close()
			os.Remove(destinationFile.Name())
		})

		_, err = io.Copy(destinationFile, sourceFile)
		require.NoError(t, err)

		fp, err := os.OpenFile("./testdata/golang/raw-results.json", os.O_RDONLY, 0666)
		require.NoError(t, err)

		var vulns models.VulnerabilityResults
		require.NoError(t, json.NewDecoder(fp).Decode(&vulns))

		resultTransformer, err := New(config.Config{
			Root: ".",
		})
		require.NoError(t, err)
		findings, err := resultTransformer.Transform(testCtx, vulns)
		require.NoError(t, err)

		for _, res := range golang.Results {
			smithytesting.AssertVulnerabilityFindingIsValid(t, res)
		}

		smithytesting.AssertFindingListsMatch(t, golang.Results, findings)
	})

	t.Run("parse elixir results", func(t *testing.T) {
		fp, err := os.OpenFile("./testdata/elixir/raw-results.json", os.O_RDONLY, 0666)
		require.NoError(t, err)

		var vulns models.VulnerabilityResults
		require.NoError(t, json.NewDecoder(fp).Decode(&vulns))

		resultTransformer, err := New(config.Config{
			Root: ".",
		})
		require.NoError(t, err)
		findings, err := resultTransformer.Transform(testCtx, vulns)
		require.NoError(t, err)

		for _, res := range elixir.Results {
			smithytesting.AssertVulnerabilityFindingIsValid(t, res)
		}

		smithytesting.AssertFindingListsMatch(t, elixir.Results, findings)
	})

	t.Run("parse javascript results", func(t *testing.T) {
		fp, err := os.OpenFile("./testdata/javascript/raw-results.json", os.O_RDONLY, 0666)
		require.NoError(t, err)

		var vulns models.VulnerabilityResults
		require.NoError(t, json.NewDecoder(fp).Decode(&vulns))

		resultTransformer, err := New(config.Config{
			Root: ".",
		})
		require.NoError(t, err)
		findings, err := resultTransformer.Transform(testCtx, vulns)
		require.NoError(t, err)

		for _, res := range elixir.Results {
			smithytesting.AssertVulnerabilityFindingIsValid(t, res)
		}

		smithytesting.AssertFindingListsMatch(t, javascript.Results, findings)
	})
}
