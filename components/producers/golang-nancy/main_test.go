package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/components/producers/golang-nancy/types"
)

func TestParseOut(t *testing.T) {
	var results types.NancyOut
	err := json.Unmarshal([]byte(exampleOutput), &results)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
	issues := parseOut(&results)

	expectedIssues := make([]*v1.Issue, 3)
	expectedIssues[0] = &v1.Issue{
		Target:     "pkg:golang/github.com/coreos/etcd@0.5.0-alpha.5",
		Type:       "Vulnerable Dependency",
		Title:      "[CVE-2018-1099]  Improper Input Validation",
		Severity:   v1.Severity_SEVERITY_MEDIUM,
		Cvss:       5.5,
		Confidence: v1.Confidence_CONFIDENCE_HIGH,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\n",
			"5.5", "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "CVE-2018-1099",
			"", "https://ossindex.sonatype.org/vuln/8a190129-526c-4ee0-b663-92f38139c165"),
		Cve: "CVE-2018-1099",
	}
	expectedIssues[1] = &v1.Issue{
		Target:     "pkg:golang/github.com/coreos/etcd@0.5.0-alpha.5",
		Type:       "Vulnerable Dependency",
		Title:      "[CVE-2018-1098]  Cross-Site Request Forgery (CSRF)",
		Severity:   v1.Severity_SEVERITY_HIGH,
		Cvss:       8.8,
		Confidence: v1.Confidence_CONFIDENCE_HIGH,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\n",
			"8.8", "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "CVE-2018-1098",
			"", "https://ossindex.sonatype.org/vuln/5c876f5e-2814-4822-baf0-1092fc63ec25"),
		Cve: "CVE-2018-1098",
	}
	expectedIssues[2] = &v1.Issue{
		Target:     "pkg:golang/github.com/gorilla/websocket@1.2.0",
		Type:       "Vulnerable Dependency",
		Title:      "CWE-190: Integer Overflow or Wraparound",
		Severity:   v1.Severity_SEVERITY_HIGH,
		Cvss:       7.5,
		Confidence: v1.Confidence_CONFIDENCE_HIGH,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\n",
			"7.5", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "",
			"CWE-190", "https://ossindex.sonatype.org/vuln/5f259e63-3efb-4c47-b593-d175dca716b0"),
	}

	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Title == issue.Title {
				singleMatch++
				found++
				assert.Equal(t, singleMatch, 1) // assert no duplicates
				assert.EqualValues(t, expected.Type, issue.Type)
				assert.EqualValues(t, expected.Title, issue.Title)
				assert.EqualValues(t, expected.Severity, issue.Severity)
				assert.EqualValues(t, expected.Cvss, issue.Cvss)
				assert.EqualValues(t, expected.Confidence, issue.Confidence)
				assert.EqualValues(t, expected.Description, issue.Description)
				assert.EqualValues(t, expected.Cve, issue.Cve)
			}
		}
	}
	assert.Equal(t, found, len(issues)) // assert everything has been found
}

var exampleOutput = `{
	"audited": [
	  {
		"Coordinates": "pkg:golang/4d63.com/embedfiles@0.0.0-20190311033909-995e0740726f",
		"Reference": "https://ossindex.sonatype.org/component/pkg:golang/4d63.com/embedfiles@0.0.0-20190311033909-995e0740726f",
		"Vulnerabilities": [],
		"InvalidSemVer": false
	  }
	],
	"exclusions": [],
	"invalid": [],
	"num_audited": 679,
	"num_vulnerable": 6,
	"version": "0.3.1",
	"vulnerable": [
	  {
		"Coordinates": "pkg:golang/github.com/coreos/etcd@0.5.0-alpha.5",
		"Reference": "https://ossindex.sonatype.org/component/pkg:golang/github.com/coreos/etcd@0.5.0-alpha.5",
		"Vulnerabilities": [
		  {
			"Id": "8a190129-526c-4ee0-b663-92f38139c165",
			"Title": "[CVE-2018-1099]  Improper Input Validation",
			"Description": "DNS rebinding vulnerability found in etcd 3.3.1 and earlier. An attacker can control his DNS records to direct to localhost, and trick the browser into sending requests to localhost (or any other address).",
			"CvssScore": "5.5",
			"CvssVector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
			"Cve": "CVE-2018-1099",
			"Cwe": "",
			"Reference": "https://ossindex.sonatype.org/vuln/8a190129-526c-4ee0-b663-92f38139c165",
			"Excluded": false
		  },
		  {
			"Id": "5c876f5e-2814-4822-baf0-1092fc63ec25",
			"Title": "[CVE-2018-1098]  Cross-Site Request Forgery (CSRF)",
			"Description": "A cross-site request forgery flaw was found in etcd 3.3.1 and earlier. An attacker can set up a website that tries to send a POST request to the etcd server and modify a key. Adding a key is done with PUT so it is theoretically safe (can't PUT from an HTML form or such) but POST allows creating in-order keys that an attacker can send.",
			"CvssScore": "8.8",
			"CvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			"Cve": "CVE-2018-1098",
			"Cwe": "",
			"Reference": "https://ossindex.sonatype.org/vuln/5c876f5e-2814-4822-baf0-1092fc63ec25",
			"Excluded": false
		  }
		],
		"InvalidSemVer": false
	  },
	  {
		"Coordinates": "pkg:golang/github.com/gorilla/websocket@1.2.0",
		"Reference": "https://ossindex.sonatype.org/component/pkg:golang/github.com/gorilla/websocket@1.2.0",
		"Vulnerabilities": [
		  {
			"Id": "5f259e63-3efb-4c47-b593-d175dca716b0",
			"Title": "CWE-190: Integer Overflow or Wraparound",
			"Description": "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value. This can introduce other weaknesses when the calculation is used for resource management or execution control.",
			"CvssScore": "7.5",
			"CvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"Cve": "",
			"Cwe": "CWE-190",
			"Reference": "https://ossindex.sonatype.org/vuln/5f259e63-3efb-4c47-b593-d175dca716b0",
			"Excluded": false
		  }
		],
		"InvalidSemVer": false
	  }

	]
  }
`

func TestGetCWEFromTitle(t *testing.T) {
	tests := []struct {
		title    string
		expected string
	}{
		{"[CVE-2023-26125] CWE-20: Improper Input Validation", "CWE-20"},
		{"[CVE-2022-24687] CWE-noinfo", ""},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			cwe := getCWEFromTitle(tt.title)
			require.Equal(t, tt.expected, cwe)
		})
	}
}

func TestEndToEndCLIWithJSON(t *testing.T) {
	err := producers.TestEndToEnd(t, "./examples/result.json", "./examples/result.pb")
	assert.NoError(t, err)
}
