package main

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	v1protos "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/private-components/components/producers/checkmarx/testdata"
)

func TestParseIssues(t *testing.T) {
	exampleOutput := testdata.CheckmarxOut
	var results Flaws
	err := xml.Unmarshal([]byte(exampleOutput), &results)
	require.Nil(t, err)

	issues, err := parseIssues(&results)
	require.Nil(t, err)

	desc0 := SmithyDescription{
		OriginalIssueDescription: results.Flaw[0].IssueDescription,
	}
	d0, err := json.Marshal(desc0)
	require.NoError(t, err)
	desc1 := SmithyDescription{
		OriginalIssueDescription: results.Flaw[1].IssueDescription,
	}
	d1, err := json.Marshal(desc1)
	require.NoError(t, err)
	expectedIssues := []*v1protos.Issue{
		{
			Target:      "/some/target:2",
			Type:        "209",
			Title:       "Recurrent - High - WebGoat",
			Severity:    v1protos.Severity_SEVERITY_HIGH,
			Confidence:  v1protos.Confidence_CONFIDENCE_UNSPECIFIED,
			Source:      "165072:WebgoatMay5:WebGoat",
			Description: string(d0),
		},
		{
			Target:      "/some/target:2",
			Type:        "210",
			Title:       "Recurrent - High - WebGoat",
			Severity:    v1protos.Severity_SEVERITY_HIGH,
			Cvss:        0,
			Confidence:  v1protos.Confidence_CONFIDENCE_UNSPECIFIED,
			Source:      "165072:WebgoatMay5:WebGoat",
			Description: string(d1),
		},
	}
	require.Equal(t, expectedIssues, issues)
}
