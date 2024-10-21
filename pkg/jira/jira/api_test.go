package jira

import (
	"testing"
	"time"

	"github.com/andygrunwald/go-jira"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trivago/tgo/tcontainer"

	"github.com/smithy-security/smithy/pkg/jira/config"
	"github.com/smithy-security/smithy/pkg/jira/document"
)

var (
	sampleConfig = config.Config{
		DefaultValues: config.DefaultValues{
			Project:         "TOY",
			IssueType:       "Vulnerability",
			Components:      []string{"c1", "c2", "c3"},
			AffectsVersions: []string{"V1", "V2"},
			Labels:          []string(nil),
			CustomFields: []config.CustomField{{
				ID:        "customfield_10000",
				FieldType: "multi-value",
				Values:    []string{"foo", "bar"},
			}},
		},
		Mappings: []config.Mappings{{
			SmithyField: "cvss",
			JiraField:   "customfield_10001",
			FieldType:   "float",
		}},
	}
	t, _         = time.Parse(time.RFC3339, "2024-10-10T20:06:33Z")
	sampleResult = document.Document{
		ScanStartTime:  t,
		ScanID:         "babbb83-4627-41c6-8ba0-70ee866290e9",
		ToolName:       "spotbugs",
		Source:         "//foo/bar:baz",
		Target:         "//foo1/bar1:baz2",
		Type:           "test type",
		Title:          "Unit Test Title",
		SeverityText:   "Info",
		CVSS:           "0.000",
		ConfidenceText: "Info",
		Description:    "this is a test description",
		FirstFound:     t,
		FalsePositive:  "true",
		CVE:            "CVE-0000-99999",
		Annotations:    map[string]string{"foo": "bar", "foobar": "baz"},
		Count:          "2",
	}

	expIssue = jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				Key: "TOY",
			},
			Type: jira.IssueType{
				Name: "Vulnerability",
			},
			Description: "spotbugs detected 'Unit Test Title' at //foo1/bar1:baz2 during scan with id babbb83-4627-41c6-8ba0-70ee866290e9.\nConfidence: Info\nThis issue has been detected 2 times before\nOriginal Description is: 'this is a test description'\nspotbugs reported severity as Info\nSmithy enrichers added the following annotations:\nfoo:bar\nfoobar:baz\n\n",
			Summary:     "bar1:baz2 Unit Test Title",
			Components: []*jira.Component{
				{Name: "c1"},
				{Name: "c2"},
				{Name: "c3"},
			},
			AffectsVersions: []*jira.AffectsVersion{
				{Name: "V1"},
				{Name: "V2"},
			},
			Labels: []string(nil),
			Unknowns: tcontainer.MarshalMap{
				"customfield_10000": []map[string]string{{"value": "foo"}, {"value": "bar"}},
				"customfield_10001": 0.000,
			},
		},
	}

	sampleClient = &Client{
		JiraClient:    authJiraClient("test_user", "test_token", "test_url"),
		DryRunMode:    true,
		Config:        sampleConfig,
		DefaultFields: getDefaultFields(sampleConfig),
	}
)

func TestNewClient(t *testing.T) {
	client := NewClient("test_user", "test_token", "test_url", true, sampleConfig)
	assert.EqualValues(t, client, sampleClient)
}

func TestAuthJiraClient(t *testing.T) {
	client := authJiraClient("test_user", "test_token", "test_url")
	assert.NotEmpty(t, client)
}

func TestAssembleIssue(t *testing.T) {
	issue := sampleClient.assembleIssue(sampleResult)
	assert.EqualValues(t, &expIssue, issue)
}

func TestCreateIssue(t *testing.T) {
	require.NoError(t, sampleClient.CreateIssue(sampleResult))
}
