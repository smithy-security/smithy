package main

import (
	"encoding/json"
	"fmt"
	"log"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/testsslsh/types"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	var results []types.TestSSLFinding
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteSmithyOut("testssl.sh", parseOut(results)); err != nil {
		log.Fatal(err)
	}
}

func parseOut(results []types.TestSSLFinding) []*v1.Issue {
	issues := []*v1.Issue{}
	for _, finding := range results {
		if finding.Severity == "OK" {
			continue
		}
		description, _ := json.Marshal(finding)
		issues = append(issues, &v1.Issue{
			Target:      finding.IP,
			Type:        finding.ID,
			Severity:    SeverityToSmithy(finding.Severity),
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Title:       fmt.Sprintf("%s - %s", finding.ID, finding.Finding),
			Description: string(description),
		})

	}
	return issues
}

// SeverityToSmithy maps testssl Severity Strings to smithy struct.
func SeverityToSmithy(severity string) v1.Severity {
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
