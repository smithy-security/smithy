package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers/semgrep/types"
	"github.com/smithy-security/smithy/pkg/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exampleOutput = `
{
	"results": [
	  	{
			"check_id": "rules.go.xss.Go using template.HTML", 
			"path": "%s",
			"start": {"line": 3, "col": 11},
			"end": {"line": 3, "col": 32},
			"extra": {
				"message": "Use of this type presents a security risk: the encapsulated content should come from a trusted source, \nas it will be included verbatim in the template output.\nhttps://blogtitle.github.io/go-safe-html/\n", 
				"metavars": {},
				"metadata": {
					"cwe": [
						"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
						"CWE-105: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
					]
				}, 
				"severity": "WARNING", 
				"lines": "\t\t\treturn template.HTML(revStr)"
			}
		},
		{
			"check_id": "rules.python.grpc.GRPC Insecure Port",
			"path": "%s",
			"start": {"line": 4, "col": 5},
			"end": {"line": 4, "col": 68},
			"extra": {
				"message": "The gRPC server listening port is configured insecurely, this offers no encryption and authentication.\nPlease review and ensure that this is appropriate for the communication.  \n", 
				"metavars": {
					"$VAR": {
						"start": {"line": 19, "col": 5, "offset": 389}, 
						"end": {"line": 19, "col": 20, "offset": 404},
						"abstract_content": "insecure_server",
						"unique_id": {
							"type": "id", "value": "insecure_server",
							"kind": "Local", "sid": 8
						}
					}
				},
				"metadata": {
					"cwe": "CWE-352: Cross-Site Request Forgery (CSRF)"
				},
				"severity": "WARNING",
				"lines": "    insecure_server.add_insecure_port('[::]:{}'.format(flags.port))"
			}
 		}
	]
}
`

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
	f, err := testutil.CreateFile("semgrep_tests_vuln_code.py", code)
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f.Name())

	semgrepResults := types.SemgrepResults{}
	err = json.Unmarshal([]byte(fmt.Sprintf(exampleOutput, f.Name(), f.Name())), &semgrepResults)

	require.NoError(t, err)
	issues, err := parseIssues(semgrepResults)
	require.NoError(t, err)

	expectedIssue := &v1.Issue{
		Target:         fmt.Sprintf("file://%s:3-3", f.Name()),
		Type:           "Use of this type presents a security risk: the encapsulated content should come from a trusted source, \nas it will be included verbatim in the template output.\nhttps://blogtitle.github.io/go-safe-html/\n",
		Title:          "rules.go.xss.Go using template.HTML",
		Severity:       v1.Severity_SEVERITY_MEDIUM,
		Cvss:           0.0,
		Confidence:     v1.Confidence_CONFIDENCE_MEDIUM,
		Description:    "Use of this type presents a security risk: the encapsulated content should come from a trusted source, \nas it will be included verbatim in the template output.\nhttps://blogtitle.github.io/go-safe-html/\n\n extra lines: \t\t\treturn template.HTML(revStr)",
		ContextSegment: &code,
		Cwe:            []int32{89, 105},
	}

	assert.Equal(t, expectedIssue, issues[0])

	expectedIssue2 := &v1.Issue{
		Target:         fmt.Sprintf("file://%s:4-4", f.Name()),
		Type:           "The gRPC server listening port is configured insecurely, this offers no encryption and authentication.\nPlease review and ensure that this is appropriate for the communication.  \n",
		Title:          "rules.python.grpc.GRPC Insecure Port",
		Severity:       v1.Severity_SEVERITY_MEDIUM,
		Cvss:           0.0,
		Confidence:     v1.Confidence_CONFIDENCE_MEDIUM,
		Description:    "The gRPC server listening port is configured insecurely, this offers no encryption and authentication.\nPlease review and ensure that this is appropriate for the communication.  \n\n extra lines:     insecure_server.add_insecure_port('[::]:{}'.format(flags.port))",
		ContextSegment: &code,
		Cwe:            []int32{352},
	}

	assert.Equal(t, expectedIssue2, issues[1])
}
