package consumers

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	smithyapiv1 "github.com/smithy-security/smithy/api/proto/v1"
	components "github.com/smithy-security/smithy/deprecated-components"
	"github.com/smithy-security/smithy/pkg/putil"
)

func TestLoadToolResponse(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "smithy-test")
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(tmpDir, "smithy-test-*.pb")
	require.NoError(t, err)

	defer require.NoError(t, os.Remove(tmpFile.Name()))

	issues := []*smithyapiv1.Issue{
		{
			Target:      "/smithy/source/foobar",
			Title:       "/smithy/source/barfoo",
			Description: "/smithy/source/example.yaml",
		},
	}
	timestamp := time.Now().UTC()
	scanID := "ab3d3290-cd9f-482c-97dc-ec48bdfcc4de"
	tags := map[string]string{
		"assetID":       "someID",
		"assetPriority": "priotity",
	}
	scanTags, err := json.Marshal(tags)
	assert.NoError(t, err)

	require.NoError(t, os.Setenv(components.EnvSmithyStartTime, timestamp.Format(time.RFC3339)))
	require.NoError(t, os.Setenv(components.EnvSmithyScanID, scanID))
	require.NoError(t, os.Setenv(components.EnvSmithyScanTags, string(scanTags)))

	resultTempDir := tmpFile.Name()
	resultFile := "test-tool"
	assert.NoError(t, putil.WriteResults(resultFile, issues, resultTempDir, scanID, timestamp, tags))

	toolRes, err := putil.LoadToolResponse(resultTempDir)
	assert.NoError(t, err)

	assert.Equal(t, "test-tool", toolRes[0].GetToolName())
	assert.Equal(t, scanID, toolRes[0].GetScanInfo().GetScanUuid())
	assert.Equal(t, tags, toolRes[0].GetScanInfo().GetScanTags())
}
