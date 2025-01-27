package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/consumers/defectdojo/client"
	"github.com/smithy-security/smithy/components/consumers/defectdojo/types"
	"github.com/smithy-security/smithy/pkg/templating"
)

type ddObj struct {
	response         []*v1.LaunchToolResponse
	testCreateReq    []*types.TestCreateRequest
	findingCreateReq []*types.FindingCreateRequest
	engagementReq    []*types.EngagementRequest
	enrichedResponse []*v1.EnrichedLaunchToolResponse
}

//revive:disable:cognitive-complexity High complexity score but easy to understand
func createObjects(t *testing.T, product int, scanType string) ddObj {
	scanID := "7c78f6c9-b4b0-493c-a912-0bb0a4aaaaa0"
	times, err := time.Parse(time.RFC3339, "2023-01-19T18:09:06.370037788Z")
	require.NoError(t, err)
	timestamp := timestamppb.New(times)
	var input []*v1.LaunchToolResponse
	var enrichedInput []*v1.EnrichedLaunchToolResponse
	var testRequests []*types.TestCreateRequest
	var findingsRequests []*types.FindingCreateRequest
	engagementRequests := []*types.EngagementRequest{
		{
			Tags:        []string{"SmithyScan", scanType + "Scan", scanID},
			Name:        scanID,
			Description: "",
			TargetStart: times.Format(DojoTimeFormat), TargetEnd: times.Format(DojoTimeFormat),
			Status:                    "",
			DeduplicationOnEngagement: true, Product: int32(product),
		},
	}

	for i := 0; i <= 3; i++ {
		si := v1.ScanInfo{
			ScanUuid:      scanID,
			ScanStartTime: timestamp,
		}
		toolName := fmt.Sprintf("Tool-%d", i)
		response := &v1.LaunchToolResponse{
			ToolName: toolName,
			ScanInfo: &si,
		}
		enrichedResponse := &v1.EnrichedLaunchToolResponse{
			OriginalResults: response,
		}
		test := &types.TestCreateRequest{
			Tags:        []string{"SmithyScan", scanType + "Test", scanID},
			Title:       toolName,
			TargetStart: times.Format(DojoTestTimeFormat),
			TargetEnd:   times.Format(DojoTestTimeFormat),
			TestType:    client.DojoTestType,
		}
		var issues []*v1.Issue
		var enrichedIssues []*v1.EnrichedIssue
		for j := 0; j <= 3%(i+1); j++ {
			duplicateTimes, err := time.Parse(time.RFC3339, "2000-01-19T18:09:06.370037788Z")
			require.NoError(t, err)
			duplicateTimestamp := timestamppb.New(duplicateTimes)
			x := v1.Issue{
				Target:     fmt.Sprintf("myTarget %d-%d", i, j),
				Type:       fmt.Sprintf("type %d-%d", i, j),
				Title:      fmt.Sprintf("title %d-%d", i, j),
				Severity:   v1.Severity_SEVERITY_INFO,
				Confidence: v1.Confidence_CONFIDENCE_INFO,
			}
			y := v1.EnrichedIssue{
				RawIssue:      &x,
				FirstSeen:     response.ScanInfo.ScanStartTime,
				Count:         1,
				FalsePositive: false,
				UpdatedAt:     response.ScanInfo.ScanStartTime,
				Hash:          "d41d8cd98f00b204e9800998ecf8427e",
				Annotations: map[string]string{
					"Foo":                  fmt.Sprintf("Bar %d", i),
					"Policy.Blah.Decision": "failed",
				},
			}
			if j%2 == 0 {
				y.FirstSeen = duplicateTimestamp
				y.Count = uint64(j)
			}
			issues = append(issues, &x)
			enrichedIssues = append(enrichedIssues, &y)

			var d *string
			if scanType == "Raw" {
				desc, err := templating.TemplateStringRaw("", &x)
				if err != nil {
					panic(err)
				}
				d = desc
			} else if scanType == "Enriched" {
				desc, err := templating.TemplateStringEnriched("", &y)
				if err != nil {
					panic(err)
				}
				d = desc
			}
			findingsReq := &types.FindingCreateRequest{
				Tags:              []string{"SmithyScan", scanType + "Finding", scanID, toolName},
				Title:             x.Title,
				Date:              times.Format(DojoTimeFormat),
				Severity:          "Info",
				FilePath:          x.Target,
				NumericalSeverity: "S:I",
				FoundBy:           []int32{1},
				Description:       *d,
				Active:            true,
				Duplicate:         false,
			}
			if j%2 == 0 && scanType != "Raw" {
				findingsReq.Active = false
				findingsReq.Duplicate = true
			}
			findingsRequests = append(findingsRequests, findingsReq)
		}
		response.Issues = issues
		enrichedResponse.OriginalResults = response // duplication here is important since we use this enrichedResponse in getEnrichedIssues above
		enrichedResponse.Issues = enrichedIssues
		input = append(input, response)
		enrichedInput = append(enrichedInput, enrichedResponse)

		testRequests = append(testRequests, test)
	}
	return ddObj{
		response:         input,
		testCreateReq:    testRequests,
		findingCreateReq: findingsRequests,
		engagementReq:    engagementRequests,
		enrichedResponse: enrichedInput,
	}
}

func createFindingResponse(findingRequest *types.FindingCreateRequest) *types.FindingCreateResponse {
	return &types.FindingCreateResponse{
		Active:            findingRequest.Active,
		Cwe:               findingRequest.Cwe,
		Date:              findingRequest.Date,
		Description:       findingRequest.Description,
		Duplicate:         findingRequest.Duplicate,
		FalseP:            findingRequest.FalseP,
		FilePath:          findingRequest.FilePath,
		FoundBy:           findingRequest.FoundBy,
		Line:              findingRequest.Line,
		NumericalSeverity: findingRequest.NumericalSeverity,
		ID:                int32(rand.Intn(10)),
		Severity:          findingRequest.Severity,
		Tags:              findingRequest.Tags,
		Test:              findingRequest.Test,
		Title:             findingRequest.Title,
		UniqueIDFromTool:  findingRequest.UniqueIDFromTool,
		Verified:          findingRequest.Verified,
		VulnIDFromTool:    findingRequest.VulnIDFromTool,
	}
}

func TestHandleRawResults(t *testing.T) {
	apiKey := "test"
	dojoUser := "satuser"
	product := 64
	objects := createObjects(t, product, "Raw")
	input := objects.response
	testRequests := objects.testCreateReq
	findingsRequests := objects.findingCreateReq
	engagementRequests := objects.engagementReq
	var foundTests []*types.TestCreateRequest
	var foundFindings []*types.FindingCreateRequest
	var foundEngagements []*types.EngagementRequest

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch string(r.URL.Path) {
		case "/users":
			assert.Equal(t, r.Method, http.MethodGet)

			result := types.GetUsersResponse{
				Count: 1,
				Results: []types.DojoUser{
					{
						ID:          1,
						Username:    dojoUser,
						FirstName:   "dojo",
						LastName:    "user",
						Email:       "dojo@user.com",
						LastLogin:   "now",
						IsActive:    true,
						IsSuperuser: false,
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(result))

		case "/tests":
			testRequest := &types.TestCreateRequest{}
			require.NoError(t, json.Unmarshal(body, testRequest))
			assert.Contains(t, testRequests, testRequest)

			foundTests = append(foundTests, testRequest) // ensure each test is only registered once
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(&types.TestCreateResponse{}))
		case "/findings":
			findingRequest := &types.FindingCreateRequest{}
			require.NoError(t, json.Unmarshal(body, findingRequest))
			assert.Contains(t, findingsRequests, findingRequest)

			foundFindings = append(foundFindings, findingRequest) // ensure each finding is only registered once
			require.NoError(t, json.NewEncoder(w).Encode(createFindingResponse(findingRequest)))
		case "/engagements":
			engagementRequest := &types.EngagementRequest{}
			require.NoError(t, json.Unmarshal(body, engagementRequest))

			assert.Contains(t, engagementRequests, engagementRequest)
			foundEngagements = append(foundEngagements, engagementRequest) // ensure each engagement is only registered once
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(&types.EngagementResponse{}))
		default:
			log.Fatal("unexpected url ", r.URL.String())
		}
	}))
	defer ts.Close()
	client, err := client.DojoClient(ts.URL, apiKey, dojoUser)
	require.NoError(t, err)

	err = handleRawResults(product, client, input)
	require.NoError(t, err)

	assert.Equal(t, foundEngagements, engagementRequests)
	assert.Equal(t, foundFindings, findingsRequests)
	assert.Equal(t, foundTests, testRequests)
}

func TestHandleEnrichedResults(t *testing.T) {
	apiKey := "test"
	dojoUser := "satuser"
	product := 65

	objects := createObjects(t, product, "Enriched")
	testRequests := objects.testCreateReq
	findingsRequests := objects.findingCreateReq
	engagementRequests := objects.engagementReq
	input := objects.enrichedResponse

	var foundTests []*types.TestCreateRequest
	var foundFindings []*types.FindingCreateRequest
	var foundEngagements []*types.EngagementRequest

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch string(r.URL.String()) {
		case "/users":
			assert.Equal(t, r.Method, http.MethodGet)

			result := types.GetUsersResponse{
				Count: 1,
				Results: []types.DojoUser{
					{
						ID:          1,
						Username:    dojoUser,
						FirstName:   "dojo",
						LastName:    "user",
						Email:       "dojo@user.com",
						LastLogin:   "now",
						IsActive:    true,
						IsSuperuser: false,
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(result))

		case "/tests":
			testRequest := &types.TestCreateRequest{}
			require.NoError(t, json.Unmarshal(body, testRequest))
			assert.Contains(t, testRequests, testRequest)

			foundTests = append(foundTests, testRequest) // ensure each test is only registered once
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(&types.TestCreateResponse{}))

		case "/findings":
			findingRequest := &types.FindingCreateRequest{}
			require.NoError(t, json.Unmarshal(body, &findingRequest))
			assert.Contains(t, findingsRequests, findingRequest)
			assert.Contains(t, string(body), "Policy.Blah.Decision")
			foundFindings = append(foundFindings, findingRequest) // ensure each finding is only registered once

			require.NoError(t, json.NewEncoder(w).Encode(createFindingResponse(findingRequest)))
		case "/engagements":
			engagementRequest := &types.EngagementRequest{}
			require.NoError(t, json.Unmarshal(body, &engagementRequest))

			assert.Contains(t, engagementRequests, engagementRequest)
			foundEngagements = append(foundEngagements, engagementRequest) // ensure each engagement is only registered once
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(&types.EngagementResponse{}))
		default:
			log.Fatal("unexpected url ", r.URL.String())
		}
	}))
	defer ts.Close()
	client, err := client.DojoClient(ts.URL, apiKey, dojoUser)
	require.NoError(t, err)

	err = handleEnrichedResults(product, client, input)
	require.NoError(t, err)

	assert.Equal(t, foundEngagements, engagementRequests)
	assert.Equal(t, foundFindings, findingsRequests)
	assert.Equal(t, foundTests, testRequests)
}
