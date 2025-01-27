package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
)

func yarnToIssueSeverity(severity string) v1.Severity {
	switch severity {
	case "low":
		return v1.Severity_SEVERITY_LOW
	case "moderate":
		return v1.Severity_SEVERITY_MEDIUM
	case "high":
		return v1.Severity_SEVERITY_HIGH
	case "critical":
		return v1.Severity_SEVERITY_CRITICAL
	default:
		return v1.Severity_SEVERITY_INFO

	}
}

type yarnAuditLine struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func (yl *yarnAuditLine) UnmarshalJSON(data []byte) error {
	var typ struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &typ); err != nil {
		return err
	}

	switch typ.Type {
	case "auditSummary":
		yl.Data = new(auditSummaryData)
	case "auditAdvisory":
		yl.Data = new(auditAdvisoryData)
	case "auditAction":
		yl.Data = new(auditActionData)
	case "info":
		// ignore
	default:
		slog.Debug("Parsed unsupported type", "type", typ.Type)
	}

	type tmp yarnAuditLine // avoids infinite recursion
	return json.Unmarshal(data, (*tmp)(yl))
}

type auditActionData struct {
	Cmd        string      `json:"cmd"`
	IsBreaking bool        `json:"isBreaking"`
	Action     auditAction `json:"action"`
}

type auditAdvisoryData struct {
	Resolution auditResolution `json:"resolution"`
	Advisory   yarnAdvisory    `json:"advisory"`
}

// AsIssue returns data as a Smithy v1.Issue.
func (audit *auditAdvisoryData) AsIssue() *v1.Issue {
	return &v1.Issue{
		Target:      producers.GetPURLTarget("npm", "", audit.Advisory.ModuleName, audit.Advisory.Findings[0].Version, nil, ""),
		Type:        strconv.Itoa(audit.Advisory.ID),
		Title:       audit.Advisory.Title,
		Severity:    yarnToIssueSeverity(audit.Advisory.Severity),
		Confidence:  v1.Confidence_CONFIDENCE_HIGH,
		Description: audit.Advisory.GetDescription(),
		Cve:         strings.Join(audit.Advisory.Cves, ", "),
		Cwe:         convertStringCWEtoInt(audit.Advisory.Cwe),
	}
}

type auditSummaryData struct {
	Vulnerabilities      vulnerabilities `json:"vulnerabilities"`
	Dependencies         int             `json:"dependencies"`
	DevDependencies      int             `json:"devDependencies"`
	OptionalDependencies int             `json:"optionalDependencies"`
	TotalDependencies    int             `json:"totalDependencies"`
}

type auditAction struct {
	Action   string            `json:"action"`
	Module   string            `json:"module"`
	Target   string            `json:"target"`
	IsMajor  bool              `json:"isMajor"`
	Resolves []auditResolution `json:"resolves"`
}

type vulnerabilities struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

type yarnAdvisory struct {
	Findings           []finding         `json:"findings"`
	Metadata           *advisoryMetaData `json:"metadata"`
	VulnerableVersions string            `json:"vulnerable_versions"`
	ModuleName         string            `json:"module_name"`
	Severity           string            `json:"severity"`
	GithubAdvisoryID   string            `json:"github_advisory_id"`
	Cves               []string          `json:"cves"`
	Access             string            `json:"access"`
	PatchedVersions    string            `json:"patched_versions"`
	Updated            string            `json:"updated"`
	Recommendation     string            `json:"recommendation"`
	Cwe                []string          `json:"cwe"`
	FoundBy            *contact          `json:"found_by"`
	Deleted            bool              `json:"deleted"`
	ID                 int               `json:"id"`
	References         string            `json:"references"`
	Created            string            `json:"created"`
	ReportedBy         *contact          `json:"reported_by"`
	Title              string            `json:"title"`
	NpmAdvisoryID      interface{}       `json:"npm_advisory_id"`
	Overview           string            `json:"overview"`
	URL                string            `json:"url"`
}

func (advisory *yarnAdvisory) GetDescription() string {
	return fmt.Sprintf(
		"Vulnerable Versions: %s\nRecommendation: %s\nOverview: %s\nReferences:\n%s\nAdvisory URL: %s\n",
		advisory.VulnerableVersions,
		advisory.Recommendation,
		advisory.Overview,
		advisory.References,
		advisory.URL,
	)
}

type finding struct {
	Version  string   `json:"version"`
	Paths    []string `json:"paths"`
	Dev      bool     `json:"dev"`
	Optional bool     `json:"optional"`
	Bundled  bool     `json:"bundled"`
}

type auditResolution struct {
	ID       int    `json:"id"`
	Path     string `json:"path"`
	Dev      bool   `json:"dev"`
	Optional bool   `json:"optional"`
	Bundled  bool   `json:"bundled"`
}

type advisoryMetaData struct {
	ModuleType         string `json:"module_type"`
	Exploitability     int    `json:"exploitability"`
	AffectedComponents string `json:"affected_components"`
}

type contact struct {
	Name string `json:"name"`
}

// YarnAuditReport includes yarn audit data grouped by advisories, actions and summary.
type YarnAuditReport struct {
	AuditAdvisories []*auditAdvisoryData
	AuditActions    []*auditActionData
	AuditSummary    *auditSummaryData
}

// NewReport returns a YarnAuditReport, assuming each line is jsonline and returns any errors.
func NewReport(reportLines [][]byte) (*YarnAuditReport, []error) {
	var report YarnAuditReport

	var errs []error

	for _, line := range reportLines {
		if len(line) == 0 {
			slog.Debug("Empty line, skipping")
			continue
		}

		var auditLine yarnAuditLine
		if err := json.Unmarshal(line, &auditLine); err != nil {
			slog.Error("Error parsing JSON line", "line", line, "error", err)
			errs = append(errs, err)
		} else {
			switch x := auditLine.Data.(type) {
			case *auditSummaryData:
				report.AuditSummary = x
			case *auditAdvisoryData:
				report.AuditAdvisories = append(report.AuditAdvisories, x)
			case *auditActionData:
				report.AuditActions = append(report.AuditActions, x)
			}
		}
	}

	if report.AuditSummary != nil && report.AuditSummary.TotalDependencies == 0 {
		slog.Error("No dependencies found", "yarn_audit_summary", report.AuditSummary)
		errs = append(errs, errors.New("no dependencies found"))
	}

	if len(report.AuditAdvisories) > 0 {
		return &report, errs
	}

	return nil, errs
}

// AsIssues returns the YarnAuditReport as Smithy v1.Issue list. Currently only converts the YarnAuditReport.AuditAdvisories.
func (r *YarnAuditReport) AsIssues() []*v1.Issue {
	issues := make([]*v1.Issue, 0)

	for _, audit := range r.AuditAdvisories {
		issues = append(issues, audit.AsIssue())
	}

	return issues
}

func convertStringCWEtoInt(cwe []string) []int32 {
	var cweInts []int32
	for _, c := range cwe {
		if cweInt, err := strconv.Atoi(strings.TrimPrefix(c, "CWE-")); err == nil {
			cweInts = append(cweInts, int32(cweInt))
		} else {
			slog.Error("Error converting CWE to int", "error", err)
		}
	}
	return cweInts
}
