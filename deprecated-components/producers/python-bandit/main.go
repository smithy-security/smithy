package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"strings"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/context"

	"github.com/smithy-security/smithy/deprecated-components/producers"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	var results BanditOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues := []*v1.Issue{}
	log.Printf("handling %d results\n", len(results.Results))
	for _, res := range results.Results {
		iss, err := parseResult(res)
		if err != nil {
			log.Fatal(err)
		}
		issues = append(issues, iss)
	}

	if err := producers.WriteSmithyOut(
		"bandit",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func parseResult(r *BanditResult) (*v1.Issue, error) {
	rng := []string{}
	for _, r := range r.LineRange {
		rng = append(rng, fmt.Sprintf("%d", r))
	}
	iss := &v1.Issue{
		Target:      fmt.Sprintf("%s:%s", r.Filename, strings.Join(rng, "-")),
		Type:        r.TestID,
		Title:       r.TestName,
		Severity:    v1.Severity(v1.Severity_value[fmt.Sprintf("SEVERITY_%s", r.IssueSeverity)]),
		Cvss:        0.0,
		Confidence:  v1.Confidence(v1.Confidence_value[fmt.Sprintf("CONFIDENCE_%s", r.IssueConfidence)]),
		Description: fmt.Sprintf("%s\ncode:%s", r.IssueText, r.Code),
		Cwe:         []int32{r.IssueCWE.ID},
	}

	// Extract the code snippet, if possible
	code, err := context.ExtractCode(iss)
	if err != nil {
		slog.Warn("Failed to extract code snippet", "error", err)
		code = ""
	}
	iss.ContextSegment = &code

	return iss, nil
}

// BanditOut represents the output of a bandit run.
type BanditOut struct {
	// Errors      []string                `json:"error"`
	// GeneratedAt time.Time               `json:"generated_at"`
	// Metrics     map[string]BanditMetric `json:"metrics"`
	Results []*BanditResult `json:"results"`
}

// BanditResult represents a Bandit Result.
type BanditResult struct {
	Code            string   `json:"code"`
	Filename        string   `json:"filename"`
	IssueConfidence string   `json:"issue_confidence"`
	IssueSeverity   string   `json:"issue_severity"`
	IssueText       string   `json:"issue_text"`
	LineNumber      uint64   `json:"line_number"`
	LineRange       []uint64 `json:"line_range"`
	MoreInfo        string   `json:"more_info"`
	TestID          string   `json:"test_id"`
	TestName        string   `json:"test_name"`
	IssueCWE        struct {
		ID int32 `json:"id"`
	} `json:"issue_cwe"`
}

// // BanditMetric represents a Bandit Metric
// type BanditMetric struct {
// 	ConfidenceHigh      float32 `json:"CONFIDENCE.HIGH"`
// 	ConfidenceLow       float32 `json:"CONFIDENCE.LOW"`
// 	ConfidenceMedium    float32 `json:"CONFIDENCE.MEDIUM"`
// 	ConfidenceUndefined float32 `json:"CONFIDENCE.UNDEFINED"`
// 	SeverityHigh        float32 `json:"SEVERITY.HIGH"`
// 	SeverityLow         float32 `json:"SEVERITY.LOW"`
// 	SeverityMedium      float32 `json:"SEVERITY.MEDIUM"`
// 	SeverityUndefined   float32 `json:"SEVERITY.UNDEFINED"`
// 	Location            uint64  `json:"loc"`
// 	NoSec               uint64  `json:"nosec"`
// }
