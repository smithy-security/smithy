package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var code = `q += ' LIMIT + %(limit)s '
            params['limit'] = limit
        if offset is not None:
            q += ' OFFSET + %(offset)s '
            params['offset'] = offset
        async with conn.cursor() as cur:
            await cur.execute(q, params)
            results = await cur.fetchall()
            return [Student.from_raw(r) for r in results]`

func TestParseIssues(t *testing.T) {
	f, err := testutil.CreateFile("bandit_tests_vuln_code", code)
	require.NoError(t, err)
	defer func() { require.NoError(t, os.Remove(f.Name())) }()

	exampleOutput := fmt.Sprintf(sampleOut, f.Name(), f.Name())

	var results BanditOut
	require.NoError(t, json.Unmarshal([]byte(exampleOutput), &results))

	issues := []*v1.Issue{}
	for _, res := range results.Results {
		iss, err := parseResult(res)
		assert.Nil(t, err, fmt.Sprintf("%s", err))
		issues = append(issues, iss)
	}
	expectedIssues := []*v1.Issue{
		{
			Target:         f.Name() + ":5",
			Type:           "B404",
			Title:          "blacklist",
			Severity:       v1.Severity_SEVERITY_LOW,
			Cvss:           0,
			Confidence:     v1.Confidence_CONFIDENCE_HIGH,
			Description:    "Consider possible security implications associated with the subprocess module.\ncode:17 import shutil\n18 import subprocess\n19 import sys\n",
			Source:         "",
			Cve:            "",
			Uuid:           "",
			ContextSegment: &code,
			Cwe:            []int32{78},
		},
		{
			Target:         f.Name() + ":6",
			Type:           "B603",
			Title:          "subprocess_without_shell_equals_true",
			Severity:       v1.Severity_SEVERITY_LOW,
			Cvss:           0,
			Confidence:     v1.Confidence_CONFIDENCE_HIGH,
			Description:    "subprocess call - check for execution of untrusted input.\ncode:104             try:\n105                 output = subprocess.check_output(bandit_command)\n106             except subprocess.CalledProcessError as e:\n",
			Source:         "",
			Cve:            "",
			Uuid:           "",
			ContextSegment: &code,
			Cwe:            []int32{78},
		},
	}

	require.Equal(t, expectedIssues, issues)
}

var sampleOut = `{
	"results": [
		{
			"code": "17 import shutil\n18 import subprocess\n19 import sys\n",
			"col_offset": 0,
			"end_col_offset": 17,
			"filename": "%s",
			"issue_confidence": "HIGH",
			"issue_cwe": {
				"id": 78,
				"link": "https://cwe.mitre.org/data/definitions/78.html"
			},
			"issue_severity": "LOW",
			"issue_text": "Consider possible security implications associated with the subprocess module.",
			"line_number": 5,
			"line_range": [
				5
			],
			"more_info": "https://bandit.readthedocs.io/en/1.7.5/blacklists/blacklist_imports.html#b404-import-subprocess",
			"test_id": "B404",
			"test_name": "blacklist"
		},
		{
			"code": "104             try:\n105                 output = subprocess.check_output(bandit_command)\n106             except subprocess.CalledProcessError as e:\n",
			"col_offset": 25,
			"end_col_offset": 64,
			"filename": "%s",
			"issue_confidence": "HIGH",
			"issue_cwe": {
				"id": 78,
				"link": "https://cwe.mitre.org/data/definitions/78.html"
			},
			"issue_severity": "LOW",
			"issue_text": "subprocess call - check for execution of untrusted input.",
			"line_number": 6,
			"line_range": [
				6
			],
			"more_info": "https://bandit.readthedocs.io/en/1.7.5/plugins/b603_subprocess_without_shell_equals_true.html",
			"test_id": "B603",
			"test_name": "subprocess_without_shell_equals_true"
		}
	]
}`
