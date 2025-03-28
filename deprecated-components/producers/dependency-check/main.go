package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"math"
	"os"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/dependency-check/types"
)

// DependencyVulnerability represents the Vulnerability block of Dependency check scan json output format.
type DependencyVulnerability struct {
	target      string
	cvss3       float64
	cwes        []string
	notes       string
	name        string
	severity    string
	cvss2       float64
	description string
	cve         string
}

// UnmarshalJSON returns a list of Dependency Vulns from dependency check json.
func UnmarshalJSON(jsonBytes []byte) []DependencyVulnerability {
	var result []DependencyVulnerability
	var report types.DependencyCheckReport

	if !json.Valid(jsonBytes) {
		log.Fatal("Inputfile not valid JSON")
	}
	if err := json.Unmarshal(jsonBytes, &report); err != nil {
		log.Fatal(err)
	}

	for _, dependency := range report.Dependencies {
		var target string
		if len(dependency.Packages) > 0 {
			target = dependency.Packages[0].ID
		} else {
			target = dependency.FilePath
		}

		for _, vuln := range dependency.Vulnerabilities {
			cvss3 := math.Max(vuln.Cvssv3.BaseScore, 0.0)
			cvss2 := math.Max(vuln.Cvssv2.Score, 0.0)
			cve := ""
			if vuln.Source == "NVD" || vuln.Source == "OSSINDEX" {
				cve = vuln.Name
			}

			result = append(result, DependencyVulnerability{
				target: target,
				cvss3:  cvss3,
				cvss2:  cvss2,
				cve:    cve,

				cwes:        vuln.Cwes,
				notes:       vuln.Notes,
				name:        vuln.Name,
				severity:    vuln.Severity,
				description: vuln.Description,
			})
		}
	}
	return result
}

func parseIssues(out []DependencyVulnerability) []*v1.Issue {
	issues := []*v1.Issue{}
	for _, r := range out {
		// Prefer CVSS v3 if available
		cvss := r.cvss2
		if r.cvss3 != 0.0 {
			cvss = r.cvss3
		}

		// Ensure target is a valid pURL
		purlTarget, err := producers.EnsureValidPURLTarget(r.target)
		if err != nil {
			slog.Error(fmt.Sprintf("Error parsing PURL: %s\n", err))
		}

		issues = append(issues, &v1.Issue{
			Target:      purlTarget,
			Type:        "Vulnerable Dependency",
			Title:       r.target,
			Severity:    v1.Severity(v1.Severity_value[fmt.Sprintf("SEVERITY_%s", r.severity)]),
			Cvss:        cvss,
			Description: r.description,
			Cve:         r.cve,
		})
	}
	return issues
}

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	jsonBytes, err := os.ReadFile(producers.InResults)
	if err != nil {
		log.Fatal(err)
	}

	issues := UnmarshalJSON(jsonBytes)
	if err := producers.WriteSmithyOut(
		"dependencyCheck",
		parseIssues(issues),
	); err != nil {
		log.Fatal(err)
	}
}
