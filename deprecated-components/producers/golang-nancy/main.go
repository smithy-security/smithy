package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"regexp"
	"strconv"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers/golang-nancy/types"

	"github.com/smithy-security/smithy/deprecated-components/producers"
)

var CWERegex = regexp.MustCompile(`CWE-\d+`)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	var results types.NancyOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	// For each result, set the cwe manually
	for _, res := range results.Vulnerable {
		for _, vuln := range res.Vulnerabilities {
			vuln.Cwe = getCWEFromTitle(vuln.Title)
		}
	}

	if err := producers.WriteSmithyOut(
		"nancy",
		parseOut(&results),
	); err != nil {
		log.Fatal(err)
	}
}

func getCWEFromTitle(title string) string {
	// Input would look like the below
	// [CVE-2023-26125] CWE-20: Improper Input Validation
	matches := CWERegex.FindStringSubmatch(title)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func parseOut(results *types.NancyOut) []*v1.Issue {
	issues := []*v1.Issue{}
	for _, res := range results.Vulnerable {
		target := res.Coordinates
		for _, vuln := range res.Vulnerabilities {
			issues = append(issues, parseResult(vuln, target))
		}
	}
	return issues
}

func cvssToSeverity(score string) v1.Severity {
	switch s, err := strconv.ParseFloat(score, 64); err == nil {
	case 0.1 <= s && s <= 3.9:
		return v1.Severity_SEVERITY_LOW
	case 4.0 <= s && s <= 6.9:
		return v1.Severity_SEVERITY_MEDIUM
	case 7.0 <= s && s <= 8.9:
		return v1.Severity_SEVERITY_HIGH
	case 9.0 <= s && s <= 10.0:
		return v1.Severity_SEVERITY_CRITICAL
	default:
		return v1.Severity_SEVERITY_INFO

	}
}

func parseResult(r *types.NancyVulnerabilities, target string) *v1.Issue {
	cvss, err := strconv.ParseFloat(r.CvssScore, 64)
	if err != nil {
		cvss = 0.0
	}

	purlTarget, err := producers.EnsureValidPURLTarget(target)
	if err != nil {
		slog.Error(fmt.Sprintf("Error parsing PURL: %s\n", err))
	}

	return &v1.Issue{
		Target:     purlTarget,
		Type:       "Vulnerable Dependency",
		Title:      r.Title,
		Severity:   cvssToSeverity(r.CvssScore),
		Confidence: v1.Confidence_CONFIDENCE_HIGH,
		Cvss:       cvss,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\n",
			r.CvssScore, r.CvssVector, r.Cve, r.Cwe, r.Reference),
		Cve: r.Cve,
	}
}
