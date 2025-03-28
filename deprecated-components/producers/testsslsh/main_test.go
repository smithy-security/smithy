package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers/testsslsh/types"
)

func TestParseOut(t *testing.T) {
	var results []types.TestSSLFinding
	err := json.Unmarshal([]byte(exampleOutput), &results)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
	issues := parseOut(results)
	expectedIssues := []*v1.Issue{
		{
			Target:      "badssl.com/104.154.89.105",
			Type:        "TLS1_1",
			Title:       "TLS1_1 - offered (deprecated)",
			Severity:    2,
			Description: `{"id":"TLS1_1","ip":"badssl.com/104.154.89.105","port":"443","severity":"LOW","finding":"offered (deprecated)"}`,
		},
		{
			Target:      "badssl.com/104.154.89.105",
			Type:        "service",
			Title:       "service - HTTP",
			Severity:    1,
			Description: `{"id":"service","ip":"badssl.com/104.154.89.105","port":"443","severity":"INFO","finding":"HTTP"}`,
		},
	}

	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Type == issue.Type {
				singleMatch++
				found++
				assert.Equal(t, singleMatch, 1) // assert no duplicates
				assert.EqualValues(t, expected.Type, issue.Type)
				assert.EqualValues(t, expected.Title, issue.Title)
				assert.EqualValues(t, expected.Severity, issue.Severity)
				assert.EqualValues(t, expected.Cvss, issue.Cvss)
				assert.EqualValues(t, expected.Confidence, issue.Confidence)
				assert.EqualValues(t, expected.Description, issue.Description)
			}
		}
	}
	assert.Equal(t, found, len(issues)) // assert everything has been found
}

var exampleOutput = `
[
         {
              "id"           : "service",
              "ip"           : "badssl.com/104.154.89.105",
              "port"         : "443",
              "severity"     : "INFO",
              "finding"      : "HTTP"
          }
,         {
	"id"           : "SSLv2",
	"ip"           : "badssl.com/104.154.89.105",
	"port"         : "443",
	"severity"     : "OK",
	"finding"      : "not offered"
		}
,         {
	"id"           : "TLS1_1",
	"ip"           : "badssl.com/104.154.89.105",
	"port"         : "443",
	"severity"     : "LOW",
	"finding"      : "offered (deprecated)"
}      

]
`
