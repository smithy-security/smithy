package main

import (
	"encoding/json"
	"log"
	"log/slog"

	v1 "github.com/ocurity/dracon/api/proto/v1"

	"github.com/ocurity/dracon/components/producers"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	var results ModelScanOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues, err := parseIssues(&results)
	if err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteDraconOut(
		"modelscan",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func parseIssues(out *ModelScanOut) ([]*v1.Issue, error) {
	issues := make([]*v1.Issue, 0, len(out.Issues))
	slog.Info("found Critical issues", slog.Int("numCrit", out.Summary.TotalIssuesBySeverity.Critical))
	slog.Info("found High issues", slog.Int("numCrit", out.Summary.TotalIssuesBySeverity.High))
	slog.Info("found Medium issues", slog.Int("numCrit", out.Summary.TotalIssuesBySeverity.Medium))
	slog.Info("found Low issues", slog.Int("numCrit", out.Summary.TotalIssuesBySeverity.Low))
	for _, issue := range out.Issues {
		issues = append(issues,
			&v1.Issue{
				Target:      "file:///" + issue.Source,
				Type:        issue.Scanner,
				Description: issue.Description,
				Title:       issue.Description,
				Severity:    modelScanSeverityToDracon(issue.Severity),
				Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			})
	}
	return issues, nil
}

func modelScanSeverityToDracon(severity string) v1.Severity {
	switch severity {
	case "CRITICAL":
		return v1.Severity_SEVERITY_CRITICAL
	case "HIGH":
		return v1.Severity_SEVERITY_HIGH
	case "MEDIUM":
		return v1.Severity_SEVERITY_MEDIUM
	case "LOW":
		return v1.Severity_SEVERITY_LOW
	default:
		return v1.Severity_SEVERITY_UNSPECIFIED
	}
}

type ModelScanOut struct {
	Summary ModelScanSummary `json:"summary,omitempty"`
	Issues  []ModelScanIssue `json:"issues,omitempty"`
	Errors  []any            `json:"errors,omitempty"`
}

type ModelScanIssue struct {
	Description string `json:"description,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Module      string `json:"module,omitempty"`
	Source      string `json:"source,omitempty"`
	Scanner     string `json:"scanner,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

type ModelScanSummary struct {
	TotalIssuesBySeverity TotalIssuesBySeverity `json:"total_issues_by_severity,omitempty"`
	TotalIssues           int                   `json:"total_issues,omitempty"`
	InputPath             string                `json:"input_path,omitempty"`
	AbsolutePath          string                `json:"absolute_path,omitempty"`
	ModelscanVersion      string                `json:"modelscan_version,omitempty"`
	Timestamp             string                `json:"timestamp,omitempty"`
	Scanned               Scanned               `json:"scanned,omitempty"`
}

type TotalIssuesBySeverity struct {
	Low      int `json:"LOW,omitempty"`
	Medium   int `json:"MEDIUM,omitempty"`
	High     int `json:"HIGH,omitempty"`
	Critical int `json:"CRITICAL,omitempty"`
}

type Scanned struct {
	TotalScanned int      `json:"total_scanned,omitempty"`
	ScannedFiles []string `json:"scanned_files,omitempty"`
}
