package utils

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/jira/document"
)

func TestProcessEnrichedMessages(t *testing.T) {
	tstampStart, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)
	startTime := timestamppb.New(tstampStart)

	tstampFS, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	firstSeen := timestamppb.New(tstampFS)
	tstampUAT, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	updatedAt := timestamppb.New(tstampUAT)

	expectedMessage := document.Document{
		ScanStartTime:  tstampStart,
		ScanID:         "babbb83-4627-41c6-8ba0-70ee866290e9",
		ToolName:       "test",
		Source:         "//foo/bar:baz",
		Target:         "//foo1/bar1:baz2",
		Type:           "test type",
		Title:          "Unit Test Title",
		SeverityText:   "Info",
		CVSS:           "0.000",
		ConfidenceText: "Info",
		Description:    "this is a test description",
		FirstFound:     tstampFS,
		Count:          "2",
		FalsePositive:  "true",
		Hash:           "cf23df2207d99a74fbe169e3eba035e633b65d94",
		CVE:            "CVE-0000-99999",
	}

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
	messages, _ := ProcessEnrichedMessages(response, true, true, 0)
	assert.Equal(t, messages[0], expectedMessage)
}

func TestProcessRawMessages(t *testing.T) {
	tstamp, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53Z")
	require.NoError(t, err)

	startTime := timestamppb.New(tstamp)

	expectedMessage := document.Document{
		ScanStartTime:  tstamp,
		ScanID:         "babbb83-4627-41c6-8ba0-70ee866290e9",
		ToolName:       "test",
		Source:         "//foo/bar:baz",
		Target:         "//foo1/bar1:baz2",
		Type:           "test type",
		Title:          "Unit Test Title",
		SeverityText:   "Info",
		CVSS:           "0.000",
		ConfidenceText: "Info",
		Description:    "this is a test description",
		FirstFound:     tstamp,
		Count:          "1",
		FalsePositive:  "false",
		Hash:           "",
		CVE:            "CVE-0000-99999",
	}
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
	messages, _ := ProcessRawMessages(response, 0)
	assert.Equal(t, messages[0], expectedMessage)
}
