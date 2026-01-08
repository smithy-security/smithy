package reporter

import (
	"net/url"
	"testing"
	"text/template"

	"github.com/smithy-security/pkg/utils"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func getTestData() *ocsf.VulnerabilityFinding {
	dataSourceRepo := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "util/middleware/middleware.go",
		},
		LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   70,
				EndLine:     76,
				StartColumn: 4,
				EndColumn:   4,
			},
		},
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: "https://github.com/0c34/govwa",
			Reference:     "master",
		},
	}
	dataSourceRepoJson, _ := protojson.Marshal(dataSourceRepo)
	vulnerabilities := []*ocsf.Vulnerability{
		{
			Title:      utils.Ptr("Vulnerability 1"),
			Desc:       utils.Ptr("Description 1"),
			Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
			VendorName: utils.Ptr("gosec"),
			Cve: &ocsf.Cve{
				Uid:  "CVE-2022-1234",
				Desc: utils.Ptr("CVE Description"),
			},
			Cwe: &ocsf.Cwe{
				Caption: utils.Ptr("CWE-79"),
				SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
			},
		},
		{
			Title:      utils.Ptr("Vulnerability 2"),
			Desc:       utils.Ptr("Description 2"),
			Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
			VendorName: utils.Ptr("semgrep"),
			Cwe: &ocsf.Cwe{
				Caption: utils.Ptr("CWE-89"),
				SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
			},
		},
		{
			Title:      utils.Ptr("Vulnerability 3"),
			Desc:       utils.Ptr("Description 3"),
			Severity:   utils.Ptr("SEVERITY_ID_CRITICAL"),
			VendorName: utils.Ptr("snyk"),
			Cve: &ocsf.Cve{
				Uid: "CVE-2023-5678",
			},
		},
	}
	return &ocsf.VulnerabilityFinding{
		FindingInfo: &ocsf.FindingInfo{
			DataSources: []string{
				string(dataSourceRepoJson),
			},
		},
		ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
		Confidence:      utils.Ptr("High"),
		SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
		Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
		Vulnerabilities: vulnerabilities,
		Message:         utils.Ptr("Test message"),
	}
}
func TestNewIssueData(t *testing.T) {
	conf := &Conf{
		SmithyDashURL:      &url.URL{Host: "example.com"},
		SmithyInstanceID:   "instance-id",
		SmithyInstanceName: "instance-name",
	}

	t.Run("nil finding", func(t *testing.T) {
		_, err := NewIssueData(nil, conf)
		if err == nil || err.Error() != "finding or finding.Finding is nil" {
			t.Errorf("expected error for nil finding, got %v", err)
		}
	})

	t.Run("nil configuration", func(t *testing.T) {
		finding := &vf.VulnerabilityFinding{
			ID:      12345,
			Finding: getTestData(),
		}
		_, err := NewIssueData(finding, nil)
		if err == nil || err.Error() != "configuration is nil" {
			t.Errorf("expected error for nil configuration, got '%v'", err)
		}
	})

	t.Run("valid finding. not enriched, default values", func(t *testing.T) {
		finding := &vf.VulnerabilityFinding{
			ID:      12345,
			Finding: getTestData(),
		}
		issueData, err := NewIssueData(finding, conf)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if issueData.FindingID != 12345 {
			t.Errorf("expected FindingID 12345, got %d", issueData.FindingID)
		}
		if issueData.Priority != "High" {
			t.Errorf("expected Priority High, got %s", issueData.Priority)
		}
		if issueData.Description != "Test message" {
			t.Errorf("expected Description 'Test message', got %s", issueData.Description)
		}
	})
}

func TestIssueData_EnrichWithNewVulnerability(t *testing.T) {
	issueData := IssueData{}

	t.Run("valid vulnerability", func(t *testing.T) {
		vulnerability := getTestData().Vulnerabilities[0]

		updatedIssueData, err := issueData.EnrichWithNewVulnerability(vulnerability)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if updatedIssueData.Tool != "gosec" {
			t.Errorf("expected Tool 'gosec', got %s", updatedIssueData.Tool)
		}
		if updatedIssueData.CWE != "CWE-79" {
			t.Errorf("expected CWE 'CWE-79', got %s", updatedIssueData.CWE)
		}
		if updatedIssueData.CVE != "CVE-2022-1234" {
			t.Errorf("expected CVE 'CVE-2022-1234', got %s", updatedIssueData.CVE)
		}
		if updatedIssueData.Priority != "Medium" {
			t.Errorf("expected Priority 'Medium', got %s", updatedIssueData.Priority)
		}
		if updatedIssueData.Description != "Description 1" {
			t.Errorf("expected Description 'Description 1', got %s", updatedIssueData.Description)
		}
		if updatedIssueData.Title != "Vulnerability 1" {
			t.Errorf("expected Title 'Vulnerability 1', got %s", updatedIssueData.Title)
		}
	})
}

func TestIssueData_String(t *testing.T) {
	issueData := IssueData{
		Title:       "Test Title",
		Description: "Test Description",
	}

	tpl, err := template.New("test").Parse("Title: {{.Title}}, Description: {{.Description}}")
	if err != nil {
		t.Fatalf("unexpected error creating template: %v", err)
	}

	t.Run("valid template", func(t *testing.T) {
		result, err := issueData.String(tpl)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		expected := "Title: Test Title, Description: Test Description"
		if result != expected {
			t.Errorf("expected %s, got %s", expected, result)
		}
	})

	t.Run("invalid template", func(t *testing.T) {
		invalidTpl, err := template.New("test").Parse("{{.InvalidField}}")
		if err != nil {
			t.Fatalf("unexpected error creating template: %v", err)
		}
		_, err = issueData.String(invalidTpl)
		if err == nil {
			t.Errorf("expected error for invalid template, got nil")
		}
	})
}

func TestIssueData_getPriority(t *testing.T) {
	issueData := IssueData{}

	tests := []struct {
		severity string
		expected string
	}{
		{ocsf.VulnerabilityFinding_SEVERITY_ID_LOW.String(), "Low"},
		{ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String(), "Medium"},
		{ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String(), "High"},
		{ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String(), "Highest"},
		{"Unknown", "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.severity, func(t *testing.T) {
			result := issueData.getPriority(test.severity)
			if result != test.expected {
				t.Errorf("expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestIssueData_getConfidence(t *testing.T) {
	issueData := IssueData{}

	tests := []struct {
		confidence ocsf.VulnerabilityFinding_ConfidenceId
		expected   string
	}{
		{ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW, "Low"},
		{ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM, "Medium"},
		{ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH, "High"},
		{ocsf.VulnerabilityFinding_CONFIDENCE_ID_OTHER, "Low"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := issueData.getConfidence(test.confidence)
			if result != test.expected {
				t.Errorf("expected %s, got %s", test.expected, result)
			}
		})
	}
}
