package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
	clientmock "github.com/smithy-security/smithy/pkg/github/mock"
)

func TestParseIssues(t *testing.T) {
	alerts := []*github.Alert{
		{
			Number: github.Int(1),
			Rule: &github.Rule{
				Tags:        []string{"security", "external/cwe/cwe-022"},
				Severity:    github.String("low"),
				Description: github.String("Test description"),
			},
			HTMLURL: github.String("https://example.com"),
			MostRecentInstance: &github.MostRecentInstance{
				Location: &github.Location{
					Path:      github.String("spec-main/api-session-spec.ts"),
					StartLine: github.Int(917),
					EndLine:   github.Int(918),
				},
				Message: &github.Message{
					Text: github.String("Test message"),
				},
			},
		},
	}

	issues := parseIssues(alerts)

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

func TestListAlertsForRepo(t *testing.T) {
	createdAt, err := time.Parse(time.RFC3339, "2020-02-13T12:29:18Z")
	require.NoError(t, err)

	// TODO: (spyros) test for pagination if this reaches production
	expected := []*github.Alert{
		{
			Number: github.Int(10),
			Repository: &github.Repository{
				ID:     github.Int64(654654654),
				NodeID: github.String("MDEwOlJlcG9zaXRvcnkxMjk2MjY5"),
				Owner: &github.User{
					Login: github.String("foo"),
				},
				Name:     github.String("bar"),
				FullName: github.String("foo/bar"),
			},
			RuleID:          github.String("1234"),
			RuleSeverity:    github.String("high"),
			RuleDescription: github.String("this is a high alert for foo/bar"),
			Rule: &github.Rule{
				ID:       github.String("js/zipslip"),
				Severity: github.String("error"),
			},
			Tool: &github.Tool{
				Name:    github.String("CodeQL"),
				Version: github.String("2.4.0"),
			},
			CreatedAt: &github.Timestamp{
				Time: createdAt,
			},
			State: github.String("open"),
		}, {
			Number: github.Int(11),
			Repository: &github.Repository{
				ID:     github.Int64(654654654),
				NodeID: github.String("ADEwOlJlcG9zaXRvcnkxMjk2MjY5"),
				Owner: &github.User{
					Login: github.String("foo"),
				},
				Name:     github.String("bar1"),
				FullName: github.String("foo/bar1"),
			},
			RuleID:          github.String("1235"),
			RuleSeverity:    github.String("high"),
			RuleDescription: github.String("this is a high alert for foo/bar1"),
			Rule: &github.Rule{
				ID:       github.String("js/zipslip1"),
				Severity: github.String("error"),
			},
			Tool: &github.Tool{
				Name:    github.String("CodeQL"),
				Version: github.String("2.4.0"),
			},
			CreatedAt: &github.Timestamp{
				Time: createdAt,
			},
			State: github.String("open"),
		},
	}
	mockGithubClient := clientmock.NewMockClient()
	mockGithubClient.ListRepoAlertsCallback = func(_, _ string, _ *github.AlertListOptions) ([]*github.Alert, *github.Response, error) {
		return expected, &github.Response{Response: &http.Response{StatusCode: 200}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts, err := listAlertsForRepo(ctx, mockGithubClient, "foo", "foo/bar", "CodeQL", "")
	require.NoError(t, err)
	require.Equal(t, alerts, expected)
}
