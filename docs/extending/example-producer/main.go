package main

import (
	"encoding/json"
	"fmt"
	"log"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

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

	var results ExampleToolOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues := parseIssues(&results)

	if err := producers.WriteSmithyOut(
		"example-tool",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func parseIssues(out *ExampleToolOut) []*v1.Issue {
	issues := []*v1.Issue{}
	for _, r := range out.Issues {
		issues = append(issues, &v1.Issue{
			Target:      fmt.Sprintf("%s:%v", r.File, r.Line),
			Type:        r.RuleID,
			Title:       r.Details,
			Severity:    v1.Severity(v1.Severity_value[fmt.Sprintf("SEVERITY_%s", r.Severity)]),
			Cvss:        0.0,
			Confidence:  v1.Confidence(v1.Confidence_value[fmt.Sprintf("CONFIDENCE_%s", r.Confidence)]),
			Description: r.Code,
		})
	}
	return issues
}

// ExampleToolOut represents the output of an ExampleTool run.
type ExampleToolOut struct {
	Issues []ExampleToolIssue `json:"Issues"`
}

// ExampleToolIssue represents an Example Tool Result.
type ExampleToolIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Line       string `json:"line"`
	Column     string `json:"column"`
}

// `
// {
// 	"Issues": [
// 		{
// 			"severity": "MEDIUM",
// 			"confidence": "HIGH",
// 			"rule_id": "G304",
// 			"details": "Potential file inclusion via variable",
// 			"file": "/tmp/source/foo.go",
// 			"code": "ioutil.ReadFile(path)",
// 			"line": "33",
// 			"column": "44"
// 		},
// 		{
// 			"severity": "MEDIUM",
// 			"confidence": "HIGH",
// 			"rule_id": "G304",
// 			"details": "Potential file inclusion via variable",
// 			"file": "/tmp/source/foo.go",
// 			"code": "ioutil.ReadFile(path)",
// 			"line": "33",
// 			"column": "44"
// 		},
// 		{
// 			"severity": "MEDIUM",
// 			"confidence": "HIGH",
// 			"rule_id": "G304",
// 			"details": "Potential file inclusion via variable",
// 			"file": "/tmp/source/foo.go",
// 			"code": "ioutil.ReadFile(path)",
// 			"line": "33",
// 			"column": "44"
// 		}
// 	],
// 	"Stats": {
// 		"files": 1,
// 		"lines": 60,
// 		"nosec": 0,
// 		"found": 1
// 	}
// }`
