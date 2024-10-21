package sarif

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_ParseOut(t *testing.T) {
	exampleOutput, err := os.ReadFile("./testdata/example_output.json")
	require.NoError(t, err)

	results, err := sarif.FromString(string(exampleOutput))
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}

	expectedIssues := []*v1.Issue{
		{
			Target:      "main.go:83-83",
			Type:        "G404",
			Title:       "[test for missing endLine, common in some tools]",
			Severity:    v1.Severity_SEVERITY_HIGH,
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "Message: [test for missing endLine, common in some tools]",
		},
		{
			Target:      "main.go:83-83",
			Type:        "G404",
			Title:       "Use of weak random number generator (math/rand instead of crypto/rand)",
			Severity:    v1.Severity_SEVERITY_HIGH,
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "Message: Use of weak random number generator (math/rand instead of crypto/rand)",
		},
		{
			Target:      "main.go:347-347",
			Type:        "G104",
			Title:       "Errors unhandled.",
			Severity:    v1.Severity_SEVERITY_MEDIUM,
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "Message: Errors unhandled.",
		},
	}
	for _, run := range results.Runs {
		rules := make(map[string]*sarif.ReportingDescriptor)
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		issues := parseOut(*run, rules, "trivy")

		assert.EqualValues(t, expectedIssues, issues)
	}
}

func Test_ToSmithy(t *testing.T) {
	trivyOutput, err := os.ReadFile("./testdata/trivy_output.json")
	require.NoError(t, err)

	var issues []*SmithyIssueCollection
	issues, err = ToSmithy(string(trivyOutput))
	require.NoError(t, err)

	expectedIssues := []*v1.Issue{
		{
			Target:      "library/ubuntu:1-1",
			Type:        "CVE-2016-20013",
			Title:       "Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)",
			Severity:    v1.Severity_SEVERITY_INFO,
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "Message: Package: libc6\nInstalled Version: 2.35-0ubuntu3\nVulnerability CVE-2016-20013\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)",
		},
	}
	for _, issue := range issues {
		assert.EqualValues(t, issue.ToolName, "Trivy")
		assert.EqualValues(t, expectedIssues, issue.Issues)
	}
}

func Test_FromSmithyEnrichedIssuesRun(t *testing.T) {
	scanStartTime := "2020-04-13T11:51:53Z"
	tstampStart, err := time.Parse(time.RFC3339, scanStartTime)
	require.NoError(t, err)

	startTime := timestamppb.New(tstampStart)
	tstampFS, err := time.Parse(time.RFC3339, scanStartTime)
	require.NoError(t, err)

	firstSeen := timestamppb.New(tstampFS)
	tstampUAT, err := time.Parse(time.RFC3339, scanStartTime)
	require.NoError(t, err)

	updatedAt := timestamppb.New(tstampUAT)
	scanUUID := "babbb83-4627-41c6-8ba0-70ee866290e9"
	responses := []*v1.EnrichedLaunchToolResponse{
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
					ScanUuid:      scanUUID,
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
					Annotations: map[string]string{
						"Policy":    "fail",
						"footag":    "bartag",
						"Signature": "blah",
					},
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
				{
					FirstSeen:     firstSeen,
					UpdatedAt:     updatedAt,
					Hash:          "cf23df2207d99a74fbe169e3eba035e633b65d94",
					FalsePositive: false,
					Count:         1,
					Annotations: map[string]string{
						"Policy":    "fail",
						"footag":    "bartag",
						"Signature": "blah",
					},
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
	typ := "test type"
	level := "note"
	msg := "this is a test description"
	uri := "//foo1/bar1:baz2"
	ruleIndex := uint(0)
	fp := "False Positive:false"
	hash := "Hash:cf23df2207d99a74fbe169e3eba035e633b65d94"
	policy := "Policy:fail"
	foo := "footag:bartag"
	sign := "Signature:blah"
	confidence := "Confidence:CONFIDENCE_INFO"
	source := "Source://foo/bar:baz"
	cve := "CVE-0000-99999"

	expected := &sarif.Report{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
		Runs: []*sarif.Run{
			{
				AutomationDetails: &sarif.RunAutomationDetails{
					Description: &sarif.Message{
						Text: &scanStartTime,
					},
					GUID: &scanUUID,
					ID:   &scanUUID,
				},
				Tool: sarif.Tool{
					Driver: &sarif.ToolComponent{
						Name: "test",
						Rules: []*sarif.ReportingDescriptor{{
							ID: typ,
						}},
					},
				},
				Results: []*sarif.Result{
					{
						RuleID:    &typ,
						RuleIndex: &ruleIndex,
						Level:     &level,
						Message: sarif.Message{
							Text: &msg,
						},
						Locations: []*sarif.Location{
							{
								PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{
										URI: &uri,
									},
								},
							},
						},
						Attachments: []*sarif.Attachment{
							{Description: &sarif.Message{Text: &confidence}},
							{Description: &sarif.Message{Text: &source}},
							{Description: &sarif.Message{Text: &cve}},
							{Description: &sarif.Message{Text: &fp}},
							{Description: &sarif.Message{Text: &hash}},
							{Description: &sarif.Message{Text: &policy}},
							{Description: &sarif.Message{Text: &foo}},
							{Description: &sarif.Message{Text: &sign}},
						},
					},
				},
			},
		},
	}

	report, err := FromSmithyEnrichedIssuesRun(responses, false)
	require.NoError(t, err)
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)
	require.Len(t, report.Runs[0].Results[0].Attachments, len(expected.Runs[0].Results[0].Attachments))

	slices.SortFunc(expected.Runs[0].Results[0].Attachments, func(a *sarif.Attachment, b *sarif.Attachment) int {
		return strings.Compare(*(a.Description.Text), *(b.Description.Text))
	})
	slices.SortFunc(report.Runs[0].Results[0].Attachments, func(a *sarif.Attachment, b *sarif.Attachment) int {
		return strings.Compare(*(a.Description.Text), *(b.Description.Text))
	})

	require.Equal(t, expected, report)
}

func Test_FromSmithyRawIssuesRun(t *testing.T) {
	scanStartTime := "2020-04-13T11:51:53Z"
	tstampStart, err := time.Parse(time.RFC3339, scanStartTime)
	require.NoError(t, err)

	startTime := timestamppb.New(tstampStart)
	scanUUID := "babbb83-4627-41c6-8ba0-70ee866290e9"
	responses := []*v1.LaunchToolResponse{
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
				ScanUuid:      scanUUID,
				ScanStartTime: startTime,
			},
		},
	}

	typ := "test type"
	level := "note"
	msg := "this is a test description"
	uri := "//foo1/bar1:baz2"
	ruleIndex := uint(0)
	confidence := "Confidence:CONFIDENCE_INFO"
	source := "Source://foo/bar:baz"
	cve := "CVE-0000-99999"
	expected := &sarif.Report{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
		Runs: []*sarif.Run{
			{
				AutomationDetails: &sarif.RunAutomationDetails{
					Description: &sarif.Message{
						Text: &scanStartTime,
					},
					GUID: &scanUUID,
					ID:   &scanUUID,
				},
				Tool: sarif.Tool{
					Driver: &sarif.ToolComponent{
						Name: "test",
						Rules: []*sarif.ReportingDescriptor{{
							ID: typ,
						}},
					},
				},
				Results: []*sarif.Result{
					{
						RuleID:    &typ,
						RuleIndex: &ruleIndex,
						Level:     &level,
						Message: sarif.Message{
							Text: &msg,
						},
						Attachments: []*sarif.Attachment{
							{Description: &sarif.Message{Text: &confidence}},
							{Description: &sarif.Message{Text: &source}},
							{Description: &sarif.Message{Text: &cve}},
						},
						Locations: []*sarif.Location{
							{
								PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{
										URI: &uri,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	report, err := FromSmithyRawIssuesRun(responses)
	require.NoError(t, err)
	require.NotNil(t, report)
	require.EqualValues(t, report, expected)
}

func Test_smithyIssueToSarif(t *testing.T) {
	issue := &v1.Issue{
		Description: "this is a test description",
		Confidence:  v1.Confidence_CONFIDENCE_INFO,
		Severity:    v1.Severity_SEVERITY_INFO,
		Cvss:        0.0,
		Source:      "//foo/bar:baz",
		Target:      "file:///workspace/output/source-code/foo1/bar1:baz2",
		Title:       "Unit Test Title",
		Type:        "test type",
		Cve:         "CVE-0000-99999",
	}
	typ := "test type"
	level := "note"
	msg := "this is a test description"
	uri := "file://foo1/bar1:baz2"
	confidence := "Confidence:CONFIDENCE_INFO"
	source := "Source://foo/bar:baz"
	cve := "CVE-0000-99999"
	expected := &sarif.Result{
		RuleID:  &typ,
		Level:   &level,
		Message: sarif.Message{Text: &msg},
		Attachments: []*sarif.Attachment{
			{Description: &sarif.Message{Text: &confidence}},
			{Description: &sarif.Message{Text: &source}},
			{Description: &sarif.Message{Text: &cve}},
		},
		Locations: []*sarif.Location{
			{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{
						URI: &uri,
					},
				},
			},
		},
	}

	sarifResults, err := smithyIssueToSarif(issue, &sarif.ReportingDescriptor{ID: typ})
	require.NoError(t, err)
	require.NotNil(t, sarifResults)
	require.EqualValues(t, sarifResults, expected)
}
