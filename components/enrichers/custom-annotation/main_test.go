package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

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
	require.NoError(t, run("foo", `{"foo":"bar"}`))

	// Check there is something in our output directory
	files, err := os.ReadDir(outdir)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	require.Len(t, files, 4)

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
		require.Empty(t, output.Issues)
	}
}

func TestHandlesFindings(t *testing.T) {
	indir, outdir := enrichers.SetupIODirs(t)
	annotations = `{"foo":"bar","a":"b","1":"2"}`
	name = "enricherName"

	mockLaunchToolResponses := enrichers.GetLaunchToolResponse(t)
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
	require.NoError(t, run(name, annotations))

	// Check there is something in our output directory
	files, err := os.ReadDir(outdir)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	require.Len(t, files, 4)

	// Check that both of them are EnrichedLaunchToolResponse
	// and their Issue property is not an empty list
	expected := map[string]*smithyv1.EnrichedLaunchToolResponse{
		"tool1": {
			OriginalResults: mockLaunchToolResponses[0],
			Issues: []*smithyv1.EnrichedIssue{
				{
					RawIssue: mockLaunchToolResponses[0].Issues[0],
					Annotations: map[string]string{
						"foo": "bar",
						"a":   "b",
						"1":   "2",
					},
				},
				{
					RawIssue: mockLaunchToolResponses[0].Issues[1],
					Annotations: map[string]string{
						"foo": "bar",
						"a":   "b",
						"1":   "2",
					},
				},
			},
		},
		"tool2": {
			OriginalResults: mockLaunchToolResponses[1],
			Issues: []*smithyv1.EnrichedIssue{
				{
					RawIssue: mockLaunchToolResponses[1].Issues[0],
					Annotations: map[string]string{
						"foo": "bar",
						"a":   "b",
						"1":   "2",
					},
				},
				{
					RawIssue: mockLaunchToolResponses[1].Issues[1],
					Annotations: map[string]string{
						"foo": "bar",
						"a":   "b",
						"1":   "2",
					},
				},
			},
		},
	}
	var actual smithyv1.EnrichedLaunchToolResponse
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".raw.pb") {
			continue
		}
		encodedProto, err := os.ReadFile(fmt.Sprintf("%s/%s", outdir, f.Name()))
		require.NoError(t, err)

		require.NoError(t, proto.Unmarshal(encodedProto, &actual))
		if !proto.Equal(&actual, expected[actual.OriginalResults.ToolName]) {
			require.True(t, proto.Equal(&actual, expected[actual.OriginalResults.ToolName]),
				cmp.Diff(&actual, expected[actual.OriginalResults.ToolName], protocmp.Transform()))
		}
	}
}
