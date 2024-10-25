package main

import (
	"encoding/json"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/require"
)

const exampleOutput = `
{
	"date": "2022-10-07",
	"repo": {
	  "name": "github.com/ossf-tests/scorecard-check-branch-protection-e2e",
	  "commit": "12ae42962014ee9aeb01d991ee2cd799ad6de659"
	},
	"scorecard": {
	  "version": "23b0ddb",
	  "commit": "23b0ddb8aa96356321cf31a2709723e29b15a951"
	},
	"score": 4,
	"checks": [
	  {
		"details": [
		  "Info: 'force pushes' disabled on branch 'main'",
		  "Info: 'allow deletion' disabled on branch 'main'",
		  "Warn: no status checks found to merge onto branch 'main'",
		  "Info: number of required reviewers is 2 on branch 'main'"
		],
		"score": 6,
		"reason": "branch protection is not maximal on development and all release branches",
		"name": "Branch-Protection",
		"documentation": {
		  "url": "https://github.com/ossf/scorecard/blob/23b0ddb8aa96356321cf31a2709723e29b15a951/docs/checks.md#branch-protection",
		  "short": "Determines if the default and release branches are protected with GitHub's branch protection settings."
		}
	  }
	],
	"metadata": null
  }`

func TestParseIssues(t *testing.T) {
	var results ScorecardOut
	err := json.Unmarshal([]byte(exampleOutput), &results)
	require.NoError(t, err)

	issues := parseIssues(&results)
	expectedIssue := &v1.Issue{
		Target:      "github.com/ossf-tests/scorecard-check-branch-protection-e2e:12ae42962014ee9aeb01d991ee2cd799ad6de659",
		Type:        "Branch-Protection",
		Title:       "branch protection is not maximal on development and all release branches",
		Severity:    v1.Severity_SEVERITY_MEDIUM,
		Description: "Overall Score: 4.0\nCheck Details:\nInfo: 'force pushes' disabled on branch 'main'\nInfo: 'allow deletion' disabled on branch 'main'\nWarn: no status checks found to merge onto branch 'main'\nInfo: number of required reviewers is 2 on branch 'main'",
	}

	require.Equal(t, []*v1.Issue{expectedIssue}, issues)
}
