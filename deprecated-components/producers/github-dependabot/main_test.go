package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-github/v69/github"
	"github.com/stretchr/testify/require"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
	clientmock "github.com/smithy-security/smithy/pkg/github/mock"
)

func PointerFromFloat64(a float64) *float64 {
	return &a
}

func TestParseIssues(t *testing.T) {
	alerts := dependabotAlerts
	issues := parseIssues(alerts)

	expected := []*v1proto.Issue{
		{
			Target: "pkg:pypi/django",
			Title:  "Django allows remote attackers to obtain potentially sensitive information by leveraging data exposure from the confirm_login_allowed() method, as demonstrated by discovering whether a user account is inactive",

			Severity:    v1proto.Severity_SEVERITY_MEDIUM,
			Cvss:        5.3,
			Confidence:  v1proto.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "django.contrib.auth.forms.AuthenticationForm in Django 2.0 before 2.0.2, and 1.11.8 and 1.11.9, allows remote attackers to obtain potentially sensitive information by leveraging data exposure from the confirm_login_allowed() method, as demonstrated by discovering whether a user account is inactive.",
			Source:      "",
			Cwe:         []int32{123, 124},
			Cve:         "CVE-2018-6188",
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

func TestListAlertsForRepo(t *testing.T) {
	// TODO: (spyros) test for pagination if this reaches production
	expected := dependabotAlerts
	mockGithubClient := clientmock.NewMockClient()
	mockGithubClient.ListRepoDependabotAlertsCallback = func(_, _ string, _ *github.ListAlertsOptions) ([]*github.DependabotAlert, *github.Response, error) {
		return expected, &github.Response{Response: &http.Response{StatusCode: 200}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts, err := listAlertsForRepo(ctx, mockGithubClient, "foo", "foo/bar", "", "")
	require.NoError(t, err)
	require.Equal(t, alerts, expected)
}

var dependabotAlerts = []*github.DependabotAlert{
	{
		Number: github.Int(2),
		State:  github.String("open"),
		Dependency: &github.Dependency{
			Package: &github.VulnerabilityPackage{
				Ecosystem: github.String("pip"),
				Name:      github.String("django"),
			},
			ManifestPath: github.String("a/b/requirements.txt"),
			Scope:        github.String("runtime"),
		},
		SecurityAdvisory: &github.DependabotSecurityAdvisory{
			GHSAID:      github.String("GHSA-rf4j-j272-fj86"),
			CVEID:       github.String("CVE-2018-6188"),
			Summary:     github.String("Django allows remote attackers to obtain potentially sensitive information by leveraging data exposure from the confirm_login_allowed() method, as demonstrated by discovering whether a user account is inactive"),
			Description: github.String("django.contrib.auth.forms.AuthenticationForm in Django 2.0 before 2.0.2, and 1.11.8 and 1.11.9, allows remote attackers to obtain potentially sensitive information by leveraging data exposure from the confirm_login_allowed() method, as demonstrated by discovering whether a user account is inactive."),
			Vulnerabilities: []*github.AdvisoryVulnerability{
				{
					Package: &github.VulnerabilityPackage{
						Ecosystem: github.String("pip"),
						Name:      github.String("django"),
					},
					Severity:               github.String("high"),
					VulnerableVersionRange: github.String(">= 2.0.0, < 2.0.2"),
					FirstPatchedVersion: &github.FirstPatchedVersion{
						Identifier: github.String("2.0.2"),
					},
					PatchedVersions: github.String("2.0.3"),
					VulnerableFunctions: []string{
						"doFoo()",
						"doBar()",
					},
				},
				{
					Package: &github.VulnerabilityPackage{
						Ecosystem: github.String("pip"),
						Name:      github.String("django"),
					},
					Severity:               github.String("high"),
					VulnerableVersionRange: github.String(">= 2.1.0, < 2.1.2"),
					FirstPatchedVersion: &github.FirstPatchedVersion{
						Identifier: github.String("2.1.2"),
					},
					PatchedVersions: github.String("2.1.3"),
					VulnerableFunctions: []string{
						"doFoo()",
						"doBar()",
					},
				},
			},
			Severity: github.String("medium"),
			CVSS: &github.AdvisoryCVSS{
				Score:        PointerFromFloat64(5.3),
				VectorString: github.String("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
			},
			CWEs: []*github.AdvisoryCWEs{
				{
					CWEID: github.String("CWE-123"),
					Name:  github.String("this is the name of a cwe with id 123"),
				},
				{
					CWEID: github.String("CWE-124"),
					Name:  github.String("this is the name of a cwe with id 124"),
				},
			},
			Identifiers: []*github.AdvisoryIdentifier{
				{
					Type:  github.String("GHSA"),
					Value: github.String("GHSA-rf4j-j272-fj86"),
				},
				{
					Type:  github.String("CVE"),
					Value: github.String("CVE-2018-6188"),
				},
			},
		},
		SecurityVulnerability: &github.AdvisoryVulnerability{
			Package: &github.VulnerabilityPackage{
				Ecosystem: github.String("pip"),
				Name:      github.String("django"),
			},
			Severity: github.String("medium"),
		},
	},
}
