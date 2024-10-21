package utils

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountEnrichedMessages(t *testing.T) {
	eIssue := &v1.EnrichedIssue{
		RawIssue: &v1.Issue{
			Description: "this is a test description",
			Confidence:  v1.Confidence_CONFIDENCE_INFO,
			Severity:    v1.Severity_SEVERITY_INFO,
			Cvss:        0.0,
			Source:      "//foo/bar:baz",
			Target:      "//foo1/bar1:baz2",
			Title:       "Unit Test Title",
			Type:        "test type",
			Cve:         "CVE-0000-99999",
		},
	}
	expectedMessage := 2
	response := []*v1.EnrichedLaunchToolResponse{
		{
			OriginalResults: &v1.LaunchToolResponse{
				ToolName: "test",
				Issues:   []*v1.Issue{{}},
				ScanInfo: &v1.ScanInfo{},
			},
			Issues: []*v1.EnrichedIssue{eIssue, eIssue},
		},
	}
	assert.Equal(t, expectedMessage, CountEnrichedMessages(response))
}

func TestCountRawMessages(t *testing.T) {
	eIssue := &v1.Issue{
		Description: "this is a test description",
		Confidence:  v1.Confidence_CONFIDENCE_INFO,
		Severity:    v1.Severity_SEVERITY_INFO,
		Cvss:        0.0,
		Source:      "//foo/bar:baz",
		Target:      "//foo1/bar1:baz2",
		Title:       "Unit Test Title",
		Type:        "test type",
		Cve:         "CVE-0000-99999",
	}
	expectedMessage := 3
	response := []*v1.LaunchToolResponse{{Issues: []*v1.Issue{eIssue, eIssue, eIssue}, ScanInfo: &v1.ScanInfo{}}}
	assert.Equal(t, expectedMessage, CountRawMessages(response))
}

func TestProcessEnrichedMessages(t *testing.T) {
	tstamp, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	startTime := timestamppb.New(tstamp)
	tstamp, err = time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	firstSeen := timestamppb.New(tstamp)
	tstamp, err = time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	updatedAt := timestamppb.New(tstamp)

	expectedMessage := `{"scan_start_time":"2020-04-13T11:51:53Z","scan_id":"babbb83-4627-41c6-8ba0-70ee866290e9","tool_name":"test","source":"//foo/bar:baz","target":"//foo1/bar1:baz2","type":"test type","title":"Unit Test Title","severity":1,"cvss":0,"confidence":1,"description":"this is a test description","first_found":"2020-04-13T11:51:53Z","count":2,"false_positive":true,"cve":"CVE-0000-99999"}`
	response := []*v1.EnrichedLaunchToolResponse{
		{
			OriginalResults: &v1.LaunchToolResponse{
				ToolName: "test",
				Issues: []*v1.Issue{
					{
						Description: "this is a test description",
						Confidence:  v1.Confidence_CONFIDENCE_INFO,
						Severity:    v1.Severity_SEVERITY_INFO,
						Cvss:        0.0,
						Source:      "//foo/bar:baz",
						Target:      "//foo1/bar1:baz2",
						Title:       "Unit Test Title",
						Type:        "test type",
						Cve:         "CVE-0000-99999",
					},
				},
				ScanInfo: &v1.ScanInfo{
					ScanUuid:      "babbb83-4627-41c6-8ba0-70ee866290e9",
					ScanStartTime: startTime,
				},
			},
			Issues: []*v1.EnrichedIssue{
				{
					FirstSeen:     firstSeen,
					UpdatedAt:     updatedAt,
					Hash:          "cf23df2207d99a74fbe169e3eba035e633b65d94",
					FalsePositive: true,
					Count:         2,
					RawIssue: &v1.Issue{
						Description: "this is a test description",
						Confidence:  v1.Confidence_CONFIDENCE_INFO,
						Severity:    v1.Severity_SEVERITY_INFO,
						Cvss:        0.0,
						Source:      "//foo/bar:baz",
						Target:      "//foo1/bar1:baz2",
						Title:       "Unit Test Title",
						Type:        "test type",
						Cve:         "CVE-0000-99999",
					},
				},
			},
		},
	}
	messages, err := ProcessEnrichedMessages(response)
	require.NoError(t, err)
	assert.Equal(t, messages[0], expectedMessage)
}

func TestProcessRawMessages(t *testing.T) {
	tstamp, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	startTime := timestamppb.New(tstamp)
	expectedMessage := `{"scan_start_time":"2020-04-13T11:51:53Z","scan_id":"babbb83-4627-41c6-8ba0-70ee866290e9","tool_name":"test","source":"//foo/bar:baz","target":"//foo1/bar1:baz2","type":"test type","title":"Unit Test Title","severity":1,"cvss":0,"confidence":1,"description":"this is a test description","first_found":"2020-04-13T11:51:53Z","count":1,"false_positive":false,"cve":"CVE-0000-99999"}`

	response := []*v1.LaunchToolResponse{
		{
			ToolName: "test",
			Issues: []*v1.Issue{
				{
					Description: "this is a test description",
					Confidence:  v1.Confidence_CONFIDENCE_INFO,
					Severity:    v1.Severity_SEVERITY_INFO,
					Cvss:        0.0,
					Source:      "//foo/bar:baz",
					Target:      "//foo1/bar1:baz2",
					Title:       "Unit Test Title",
					Type:        "test type",
					Cve:         "CVE-0000-99999",
				},
			},
			ScanInfo: &v1.ScanInfo{
				ScanUuid:      "babbb83-4627-41c6-8ba0-70ee866290e9",
				ScanStartTime: startTime,
			},
		},
	}
	messages, err := ProcessRawMessages(response)
	require.NoError(t, err)
	assert.Equal(t, messages[0], expectedMessage)
}

func TestPushMetrics(t *testing.T) {
	template := "Smithy scan <scanID>, started at <scanStartTime>, completed with <numResults> issues out of which, <newResults> new"
	want := "OK"
	scanUUID := "test-uuid"
	scanStartTime, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	issuesNo := 1234
	slackIn := `{"text":"Smithy scan test-uuid, started at 2020-04-13 11:51:53 +0000 UTC, completed with 1234 issues out of which, 0 new"}`
	slackStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(r.Body)
		require.NoError(t, err)
		assert.Equal(t, buf.String(), slackIn)
		w.WriteHeader(200)

		_, err = w.Write([]byte(want))
		require.NoError(t, err)
	}))
	defer slackStub.Close()
	PushMetrics(scanUUID, issuesNo, scanStartTime, 0, template, slackStub.URL)
}

func TestPush(t *testing.T) {
	testMessage := "test Message"
	want := "OK"
	slackIn := `{"text":"` + testMessage + `"}`
	slackStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		assert.Equal(t, buf.String(), slackIn)
		w.WriteHeader(200)

		_, err = w.Write([]byte(want))
		require.NoError(t, err)
	}))
	defer slackStub.Close()

	PushMessage(testMessage, slackStub.URL)
}
