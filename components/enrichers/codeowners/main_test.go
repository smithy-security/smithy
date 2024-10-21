package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/enrichers"
)

func TestHandlesZeroFindings(t *testing.T) {
	indir, outdir := enrichers.SetupIODirs(t)

	mockLaunchToolResponses := enrichers.GetEmptyLaunchToolResponse(t)
	for i, r := range mockLaunchToolResponses {
		// Write sample enriched responses to indir
		encodedProto, err := proto.Marshal(r)
		require.NoError(t, err)
		rwPermission600 := os.FileMode(0o600)

		require.NoError(t, os.WriteFile(fmt.Sprintf("%s/input_%d_%s.tagged.pb", indir, i, r.ToolName), encodedProto, rwPermission600))
	}

	// Run the enricher
	enrichers.SetReadPathForTests(indir)
	enrichers.SetWritePathForTests(outdir)
	require.NoError(t, run())

	// Check there is something in our output directory
	files, err := os.ReadDir(outdir)
	require.NoError(t, err)
	assert.NotEmpty(t, files)
	assert.Len(t, files, 4)

	// Check that both of them are EnrichedLaunchToolResponse
	// and their Issue property is an empty list
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".raw.pb") {
			continue
		}

		encodedProto, err := os.ReadFile(fmt.Sprintf("%s/%s", outdir, f.Name()))
		require.NoError(t, err)

		output := &smithyv1.EnrichedLaunchToolResponse{}
		require.NoError(t, proto.Unmarshal(encodedProto, output))

		assert.Empty(t, output.Issues)
	}
}
