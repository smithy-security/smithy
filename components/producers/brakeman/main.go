package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"strings"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/context"

	"github.com/smithy-security/smithy/components/producers"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	var results BrakemanOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues, err := parseIssues(&results)
	if err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteSmithyOut(
		"brakeman",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func handleLine(line string) (int, int) {
	// can be both "line" or "line-line"
	var start, end int
	_, err := fmt.Sscanf(line, "%d-%d", &start, &end)
	if err != nil {
		_, err := fmt.Sscanf(line, "%d", &start)
		if err != nil {
			slog.Warn("Failed to parse line", "line", line)
		}
		end = start
	}
	return start, end
}

func parseIssues(out *BrakemanOut) ([]*v1.Issue, error) {
	issues := []*v1.Issue{}
	for _, r := range out.Warnings {
		start, end := handleLine(fmt.Sprintf("%d", r.Line))
		cwe := []int32{}
		for _, c := range r.CweID {
			cwe = append(cwe, int32(c))
		}
		iss := &v1.Issue{
			Target:      producers.GetFileTarget(r.File, start, end),
			Type:        fmt.Sprintf("%s:%d", r.WarningType, r.WarningCode),
			Title:       r.Message,
			Severity:    v1.Severity_SEVERITY_UNSPECIFIED,
			Cvss:        0.0,
			Cwe:         cwe,
			Confidence:  v1.Confidence(v1.Confidence_value[fmt.Sprintf("CONFIDENCE_%s", strings.ToUpper(r.Confidence))]),
			Description: fmt.Sprintf("%s\n%s\n", r.Message, r.WarningType),
		}

		// Extract the code snippet, if possible
		code, err := context.ExtractCodeFromFileTarget(iss.Target)
		if err != nil {
			slog.Warn("Failed to extract code snippet", "error", err)
			code = ""
		}
		iss.ContextSegment = &code

		issues = append(issues, iss)
	}
	return issues, nil
}

// ScanInfo represents the scan information
type ScanInfo struct {
	AppPath             string   `json:"app_path,omitempty"`
	RailsVersion        string   `json:"rails_version,omitempty"`
	SecurityWarnings    int      `json:"security_warnings,omitempty"`
	StartTime           string   `json:"start_time,omitempty"`
	EndTime             string   `json:"end_time,omitempty"`
	Duration            float64  `json:"duration,omitempty"`
	ChecksPerformed     []string `json:"checks_performed,omitempty"`
	NumberOfControllers int      `json:"number_of_controllers,omitempty"`
	NumberOfModels      int      `json:"number_of_models,omitempty"`
	NumberOfTemplates   int      `json:"number_of_templates,omitempty"`
	RubyVersion         string   `json:"ruby_version,omitempty"`
	BrakemanVersion     string   `json:"brakeman_version,omitempty"`
}

// BrakemanLocation represents the location of the warning
type BrakemanLocation struct {
	Type       string `json:"type,omitempty"`
	Class      string `json:"class,omitempty"`
	Method     string `json:"method,omitempty"`
	Controller string `json:"controller,omitempty"`
}

// BrakemanWarning represents a warning from brakeman
type BrakemanWarning struct {
	WarningType string           `json:"warning_type,omitempty"`
	WarningCode int              `json:"warning_code,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"`
	CheckName   string           `json:"check_name,omitempty"`
	Message     string           `json:"message,omitempty"`
	File        string           `json:"file,omitempty"`
	Line        int              `json:"line,omitempty"`
	Link        string           `json:"link,omitempty"`
	Code        string           `json:"code,omitempty"`
	RenderPath  any              `json:"render_path,omitempty"`
	Location    BrakemanLocation `json:"location,omitempty"`
	UserInput   string           `json:"user_input,omitempty"`
	Confidence  string           `json:"confidence,omitempty"`
	CweID       []int            `json:"cwe_id,omitempty"`
}

// BrakemanOut represents the output of brakeman
type BrakemanOut struct {
	ScanInfo ScanInfo          `json:"scan_info,omitempty"`
	Warnings []BrakemanWarning `json:"warnings,omitempty"`
}
