package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/sign"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

func createObjects(toolRuns, issuesInEach, annotationsEach int) ([]*v1.EnrichedLaunchToolResponse, []*v1.EnrichedLaunchToolResponse) {
	scanID := "7c78f6c9-b4b0-493c-a912-0bb0a4aaaaa0"
	times, _ := time.Parse(time.RFC3339, "2023-01-19T18:09:06.370037788Z")
	timestamp := timestamppb.New(times)
	var enrichedInput []*v1.EnrichedLaunchToolResponse
	for i := 0; i < toolRuns; i++ {
		si := v1.ScanInfo{
			ScanUuid:      scanID,
			ScanStartTime: timestamp,
		}
		toolName := fmt.Sprintf("Tool-%d", i)
		response := v1.LaunchToolResponse{
			ToolName: toolName,
			ScanInfo: &si,
		}
		enrichedResponse := v1.EnrichedLaunchToolResponse{}

		var issues []*v1.Issue
		var enrichedIssues []*v1.EnrichedIssue
		for j := 0; j < issuesInEach; j++ {
			id := uuid.New()
			x := v1.Issue{
				Target:     fmt.Sprintf("target %d-%d", i, j),
				Type:       fmt.Sprintf("type %d-%d", i, j),
				Title:      fmt.Sprintf("title %d-%d", i, j),
				Severity:   v1.Severity_SEVERITY_INFO,
				Confidence: v1.Confidence_CONFIDENCE_INFO,
				Uuid:       id.String(),
			}
			y := v1.EnrichedIssue{
				RawIssue:      &x,
				FirstSeen:     response.ScanInfo.ScanStartTime,
				Count:         uint64(i),
				FalsePositive: false,
				UpdatedAt:     response.ScanInfo.ScanStartTime,
				Hash:          fmt.Sprintf("d41d8cd98f00b204e9800998ecf842%d%d", i, j),
			}
			issues = append(issues, &x)
			enrichedIssues = append(enrichedIssues, &y)
		}
		response.Issues = issues
		enrichedResponse.OriginalResults = &response
		enrichedResponse.Issues = enrichedIssues
		enrichedInput = append(enrichedInput, &enrichedResponse)
	}
	// copy each EnrichedLaunchToolResponse times "annotationsEach" and add at least one unique annotation to every issue of every copy so you can simulate multiple enrichers running on each tool
	var annotatedResults []*v1.EnrichedLaunchToolResponse
	var expectedResults []*v1.EnrichedLaunchToolResponse

	for _, response := range enrichedInput {
		expectedResult := response
		var iss []*v1.EnrichedIssue
		z := 3
		for _, issue := range response.GetIssues() {
			is := issue
			is.Annotations = map[string]string{
				fmt.Sprintf("Enricher.Annotation.%d", z): strconv.Itoa(z),
				"Conflict-Annotation":                    strconv.Itoa(z),
				"Same annotation":                        "same",
			}
			iss = append(iss, is)
		}
		expectedResult.Issues = iss
		expectedResults = append(expectedResults, expectedResult)
		for z := 0; z < annotationsEach; z++ {
			annotatedResult := response

			var newIssues []*v1.EnrichedIssue
			for _, issue := range response.GetIssues() {
				ni := issue
				ni.Annotations = map[string]string{
					fmt.Sprintf("Enricher.Annotation.%d", z): strconv.Itoa(z),
					"Conflict-Annotation":                    strconv.Itoa(z),
					"Same annotation":                        "same",
				}
				newIssues = append(newIssues, ni)
			}
			annotatedResult.Issues = newIssues
			annotatedResults = append(annotatedResults, annotatedResult)
		}
	}
	return annotatedResults, expectedResults
}

func TestSignIssues(t *testing.T) {
	// prepare
	indir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	outdir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	toolRuns := 1
	issuesInEach := 1
	expectedNumAnnotations := 1
	responses, expectedResponses := createObjects(toolRuns, issuesInEach, expectedNumAnnotations)
	for i, resp := range responses {
		// write sample enriched responses in mktemp
		out, _ := proto.Marshal(resp)
		require.NoError(t, os.WriteFile(fmt.Sprintf("%s/aggregatorSat%d.enriched.pb", indir, i), out, 0o600))
	}

	readPath = indir
	writePath = outdir

	public, private, err := sign.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signKey = base64.StdEncoding.EncodeToString(private[:])
	run()

	files, err := os.ReadDir(writePath)
	require.NoError(t, err)

	for _, file := range files {
		pbBytes, err := os.ReadFile(filepath.Join(writePath, file.Name()))
		require.NoError(t, err)

		res := v1.EnrichedLaunchToolResponse{}
		require.NoError(t, proto.Unmarshal(pbBytes, &res))

		found := false
		for _, er := range expectedResponses {
			if er.GetOriginalResults().GetToolName() == res.GetOriginalResults().GetToolName() {
				found = true
				assert.Equal(t, len(er.GetIssues()), len(res.GetIssues()))
				for _, expectedIssue := range er.GetIssues() {
					issueFound := false
					for _, otherIssue := range res.GetIssues() {
						if expectedIssue.RawIssue.Title == otherIssue.RawIssue.Title {
							decoded, err := base64.StdEncoding.DecodeString(otherIssue.Annotations[signatureAnnotation])
							require.NoError(t, err)

							_, valid := sign.Open(nil, decoded, public)
							assert.True(t, valid)
							issueFound = true
						}
					}
					assert.True(t, issueFound)
				}
			}
		}
		assert.True(t, found)
	}
}

func TestAggregateIssues(t *testing.T) {
	// prepare
	indir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	outdir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	toolRuns := 3
	issuesInEach := 4
	expectedNumAnnotations := 4
	responses, expectedResponses := createObjects(toolRuns, issuesInEach, expectedNumAnnotations)
	for i, resp := range responses {
		// write sample enriched responses in mktemp
		out, _ := proto.Marshal(resp)
		require.NoError(t, os.WriteFile(fmt.Sprintf("%s/aggregatorSat%d.enriched.pb", indir, i), out, 0o600))
	}

	signKey = ""
	readPath = indir
	writePath = outdir
	run()
	files, err := os.ReadDir(writePath)
	require.NoError(t, err)

	for _, file := range files {
		pbBytes, err := os.ReadFile(filepath.Join(writePath, file.Name()))
		require.NoError(t, err)
		res := v1.EnrichedLaunchToolResponse{}
		require.NoError(t, proto.Unmarshal(pbBytes, &res))

		found := false
		for _, er := range expectedResponses {
			if er.GetOriginalResults().GetToolName() == res.GetOriginalResults().GetToolName() {
				found = true
				assert.Equal(t, len(er.GetIssues()), len(res.GetIssues()))
				for _, issue := range er.GetIssues() {
					issueFound := false
					for _, otherIssue := range res.GetIssues() {
						if issue.RawIssue.Title == otherIssue.RawIssue.Title {
							assert.Equal(t, otherIssue.Annotations, issue.Annotations)
							issueFound = true
						}
					}
					assert.Truef(t, issueFound, "\nCould not find %#v\n", issue)
				}
			}
		}
		assert.True(t, found)
	}
}

func TestAggregateIssuesHandlesNoIssues(t *testing.T) {
	// prepare
	indir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	outdir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	// Create mock input data
	mockLaunchToolResponses := []*v1.EnrichedLaunchToolResponse{
		{
			Issues: []*v1.EnrichedIssue{},
		},
		{
			Issues: []*v1.EnrichedIssue{},
		},
	}
	for i, resp := range mockLaunchToolResponses {
		// write sample enriched responses in mktemp
		out, err := proto.Marshal(resp)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(fmt.Sprintf("%s/aggregatorSat%d.enriched.pb", indir, i), out, 0o600))
	}

	// Run the enricher
	signKey = ""
	readPath = indir
	writePath = outdir
	require.NoError(t, run())

	// Check there is something in our output directory
	files, err := os.ReadDir(outdir)
	require.NoError(t, err)
	assert.NotEmpty(t, files)
	assert.Len(t, files, 1)

	// Check that we have an EnrichedAggregatedResult with no issues
	for _, f := range files {
		encodedProto, err := os.ReadFile(fmt.Sprintf("%s/%s", outdir, f.Name()))
		require.NoError(t, err)

		output := &v1.EnrichedLaunchToolResponse{}
		require.NoError(t, proto.Unmarshal(encodedProto, output))

		assert.Empty(t, output.Issues)
	}
}
