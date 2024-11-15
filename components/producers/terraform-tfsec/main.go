package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/components/producers/terraform-tfsec/types"
	"github.com/smithy-security/smithy/pkg/context"
	"github.com/smithy-security/smithy/pkg/sarif"
)

// Sarif flag to indicate the producer is being fed sarif input.
var Sarif bool

func main() {
	flag.BoolVar(&Sarif, "sarifOut", false, "Output is in sarif format}")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	if Sarif {
		var sarifResults []*sarif.SmithyIssueCollection
		var smithyResults []*v1.Issue
		sarifResults, err := sarif.ToSmithy(string(inFile), sarif.ExtraContextLanguageUnspecified)
		if err != nil {
			log.Fatal(err)
		}
		for _, result := range sarifResults {
			if result.ToolName != "defsec" {
				log.Printf("Toolname from Sarif results is not 'defsec' it is %s instead\n", result.ToolName)
			}
			smithyResults = append(smithyResults, result.Issues...)
		}
		if err := producers.WriteSmithyOut("tfsec", smithyResults); err != nil {
			log.Fatal(err)
		}
	} else {
		var results types.TfSecOut
		if err := json.Unmarshal(inFile, &results); err != nil {
			log.Fatal(err)
		}
		issues, err := parseOut(results)
		if err != nil {
			log.Fatal(err)
		}
		if err := producers.WriteSmithyOut("tfsec", issues); err != nil {
			log.Fatal(err)
		}

	}
}

func parseOut(results types.TfSecOut) ([]*v1.Issue, error) {
	issues := []*v1.Issue{}
	for _, res := range results.Results {
		description, _ := json.Marshal(res)
		iss := &v1.Issue{
			Target: fmt.Sprintf("%s:%d-%d",
				res.Location.Filename,
				res.Location.StartLine,
				res.Location.EndLine),
			Type:        res.LongID,
			Title:       res.RuleDescription,
			Severity:    TfSecSeverityToSmithy(res.Severity),
			Confidence:  v1.Confidence_CONFIDENCE_MEDIUM,
			Description: string(description),
		}

		// Extract the code snippet, if possible
		code, err := context.ExtractCode(iss)
		if err != nil {
			slog.Warn("Failed to extract code snippet", "error", err)
			code = ""
		}
		iss.ContextSegment = &code

		issues = append(issues, iss)
	}
	return issues, nil
}

// TfSecSeverityToSmithy maps tfsec Severity Strings to smithy struct.
func TfSecSeverityToSmithy(severity string) v1.Severity {
	switch severity {
	case "LOW":
		return v1.Severity_SEVERITY_LOW
	case "MEDIUM":
		return v1.Severity_SEVERITY_MEDIUM
	case "HIGH":
		return v1.Severity_SEVERITY_HIGH
	case "CRITICAL":
		return v1.Severity_SEVERITY_CRITICAL
	default:
		return v1.Severity_SEVERITY_INFO
	}
}
