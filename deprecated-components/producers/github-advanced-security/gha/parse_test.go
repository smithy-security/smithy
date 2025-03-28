package gha

import (
	"testing"

	"github.com/google/go-github/v69/github"
	"github.com/stretchr/testify/require"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
)

func TestParseIssues(t *testing.T) {
	alerts := []*github.Alert{
		{
			Number: github.Ptr(1),
			Rule: &github.Rule{
				Tags:        []string{"security", "external/cwe/cwe-022"},
				Severity:    github.Ptr("low"),
				Description: github.Ptr("Test description"),
			},
			HTMLURL: github.Ptr("https://example.com"),
			MostRecentInstance: &github.MostRecentInstance{
				Location: &github.Location{
					Path:      github.Ptr("spec-main/api-session-spec.ts"),
					StartLine: github.Ptr(917),
					EndLine:   github.Ptr(918),
				},
				Message: &github.Message{
					Text: github.Ptr("Test message"),
				},
			},
		},
	}

	issues := ParseIssues(alerts)

	expected := []*v1proto.Issue{
		{
			Target:      "file://spec-main/api-session-spec.ts:917-918",
			Type:        "1",
			Title:       "Test description",
			Severity:    v1proto.Severity_SEVERITY_LOW,
			Cvss:        0,
			Confidence:  v1proto.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "Test message",
			Source:      "https://example.com",
			Cwe:         []int32{22},
		},
	}

	require.Equal(t, expected, issues)
}

func TestParseGitHubSeverity(t *testing.T) {
	testCases := []struct {
		name     string
		severity string
		expected v1proto.Severity
	}{
		{
			name:     "low severity",
			severity: "low",
			expected: v1proto.Severity_SEVERITY_LOW,
		},
		{
			name:     "medium severity",
			severity: "medium",
			expected: v1proto.Severity_SEVERITY_MEDIUM,
		},
		{
			name:     "high severity",
			severity: "high",
			expected: v1proto.Severity_SEVERITY_HIGH,
		},
		{
			name:     "critical severity",
			severity: "critical",
			expected: v1proto.Severity_SEVERITY_CRITICAL,
		},
		{
			name:     "unspecified severity",
			severity: "unknown",
			expected: v1proto.Severity_SEVERITY_UNSPECIFIED,
		},
		{
			name:     "empty severity",
			severity: "",
			expected: v1proto.Severity_SEVERITY_UNSPECIFIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			severity := parseGitHubSeverity(tc.severity)
			require.Equal(t, tc.expected, severity)
		})
	}
}

func TestParseGitHubCWEsFromTags(t *testing.T) {
	testCases := []struct {
		name     string
		tags     []string
		expected []int32
	}{
		{
			name:     "single CWE",
			tags:     []string{"security", "external/cwe/cwe-022"},
			expected: []int32{22},
		},
		{
			name:     "multiple CWEs",
			tags:     []string{"security", "external/cwe/cwe-022", "external/cwe/cwe-023", "external/cwe/cwe-124"},
			expected: []int32{22, 23, 124},
		},
		{
			name:     "no CWEs",
			tags:     []string{"security"},
			expected: []int32{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cwes := parseGithubCWEsFromTags(tc.tags)
			require.Equal(t, tc.expected, cwes)
		})
	}
}
