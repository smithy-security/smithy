package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/kics/types"
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
			if result.ToolName != "KICS" {
				log.Printf("Toolname from Sarif results is not 'KICS' it is %s instead\n", result.ToolName)
			}
			smithyResults = append(smithyResults, result.Issues...)
		}
		if err := producers.WriteSmithyOut("KICS", smithyResults); err != nil {
			log.Fatal(err)
		}
	} else {
		var results types.KICSOut
		if err := json.Unmarshal(inFile, &results); err != nil {
			log.Fatal(err)
		}
		res, err := parseOut(results)
		if err != nil {
			log.Fatal(err)
		}
		if err := producers.WriteSmithyOut("KICS", res); err != nil {
			log.Fatal(err)
		}

	}
}

func parseOut(results types.KICSOut) ([]*v1.Issue, error) {
	issues := []*v1.Issue{}
	for _, query := range results.Queries {
		queryCopy := query
		queryCopy.Files = make([]types.KICSFile, 1)

		for _, file := range query.Files {
			queryCopy.Files = []types.KICSFile{file}
			description, _ := json.Marshal(queryCopy)
			iss := &v1.Issue{
				Target:     fmt.Sprintf("%s:%d", file.FileName, file.Line),
				Type:       file.IssueType,
				Severity:   KICSSeverityToSmithy(query.Severity),
				Confidence: v1.Confidence_CONFIDENCE_UNSPECIFIED,
				Title: fmt.Sprintf("%s %s %s",
					query.Category,
					file.ResourceType,
					file.ResourceName),
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
	}
	return issues, nil
}

// KICSSeverityToSmithy maps KCIS Severity Strings to smithy struct.
func KICSSeverityToSmithy(severity string) v1.Severity {
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
