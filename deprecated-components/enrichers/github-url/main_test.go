package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
)

func TestHandlesFindings(t *testing.T) {
	type arguments struct {
		orgname  string
		ref      string
		repoName string
	}
	tests := []struct {
		name           string
		input          []*smithyv1.Issue
		expectedOutput []*smithyv1.EnrichedIssue
		arguments      arguments
	}{
		{
			name:           "zero input",
			input:          []*smithyv1.Issue{},
			expectedOutput: []*smithyv1.EnrichedIssue{},
		},
		{
			name: "pull request",
			arguments: arguments{
				orgname:  "fooOwner",
				ref:      "10",
				repoName: "barRepo",
			},
			input: []*smithyv1.Issue{
				{
					Target:   "file://a/b/c/d.py:1-2",
					Type:     "a",
					Title:    "ab",
					Severity: smithyv1.Severity_SEVERITY_INFO,
					Cvss:     1,
				},
			},
			expectedOutput: []*smithyv1.EnrichedIssue{
				{
					RawIssue: &smithyv1.Issue{
						Target:   "file://a/b/c/d.py:1-2",
						Type:     "a",
						Title:    "ab",
						Severity: smithyv1.Severity_SEVERITY_INFO,
						Cvss:     1,
					},
					Annotations: map[string]string{
						defaultAnnotation: "https://github.com/fooOwner/barRepo/pull/10/files#diff-3d8d72612026a0760c585ef585748a67a54cdcc1L1",
					},
				},
			},
		},
		{
			name: "commit to branch",
			arguments: arguments{
				orgname:  "fooOwner",
				ref:      "36e8e0c21ccf",
				repoName: "barRepo",
			},
			input: []*smithyv1.Issue{
				{
					Target:   "file://a/b/c/d.py:1-2",
					Type:     "a",
					Title:    "ab",
					Severity: smithyv1.Severity_SEVERITY_INFO,
					Cvss:     1,
				},
			},
			expectedOutput: []*smithyv1.EnrichedIssue{
				{
					RawIssue: &smithyv1.Issue{
						Target:   "file://a/b/c/d.py:1-2",
						Type:     "a",
						Title:    "ab",
						Severity: smithyv1.Severity_SEVERITY_INFO,
						Cvss:     1,
					},
					Annotations: map[string]string{
						defaultAnnotation: "https://github.com/fooOwner/barRepo/blob/36e8e0c21ccf/a/b/c/d.py#L1",
					},
				},
			},
		},
		{
			name: "not a file target means no enrichment",
			arguments: arguments{
				orgname:  "fooOwner",
				ref:      "36e8e0c21ccf",
				repoName: "barRepo",
			},
			input: []*smithyv1.Issue{
				{
					Target:   "pkg:foo/bar/baz@123",
					Type:     "a",
					Title:    "ab",
					Severity: smithyv1.Severity_SEVERITY_INFO,
					Cvss:     1,
				},
			},
			expectedOutput: []*smithyv1.EnrichedIssue{
				{
					RawIssue: &smithyv1.Issue{
						Target:   "pkg:foo/bar/baz@123",
						Type:     "a",
						Title:    "ab",
						Severity: smithyv1.Severity_SEVERITY_INFO,
						Cvss:     1,
					},
				},
			},
		},
		{
			name: "no line numbers, no enrichment",
			arguments: arguments{
				orgname:  "fooOwner",
				ref:      "36e8e0c21ccf",
				repoName: "barRepo",
			},
			input: []*smithyv1.Issue{
				{
					Target:   "file://foo/bar/baz.c",
					Type:     "a",
					Title:    "ab",
					Severity: smithyv1.Severity_SEVERITY_INFO,
					Cvss:     1,
				},
			},
			expectedOutput: []*smithyv1.EnrichedIssue{
				{
					RawIssue: &smithyv1.Issue{
						Target:   "file://foo/bar/baz.c",
						Type:     "a",
						Title:    "ab",
						Severity: smithyv1.Severity_SEVERITY_INFO,
						Cvss:     1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orgName = tt.arguments.orgname
			ref = tt.arguments.ref
			repoName = tt.arguments.repoName

			result := enrichIssues(tt.input)
			assert.Equal(t, len(result), len(tt.expectedOutput))
			for _, ri := range result {
				assert.Containsf(t, tt.expectedOutput, ri, "received unexpected result for test %s", tt.name)
			}
		})
	}
}
