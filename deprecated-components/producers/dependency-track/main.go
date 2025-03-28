// Package main of the dependency track producer reads a dependency track export and translates it to smithy format
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/smithy-security/smithy/deprecated-components/producers"
)

var (
	// Fetch is a boolean flag that instructs the DT producer to fetch all vulnerabilities from a specific project
	Fetch bool
	// ProjectID is only used with "Fetch", if fetch is defined, vulnerabilities of the specific projectID will be fetched
	ProjectID string

	// APIKey is the DT api key
	APIKey string

	// URL is the URL of the remote DT
	URL string
)

func main() {
	flag.BoolVar(&Fetch, "fetchVulnerabilities", false, "a boolean flag that instructs the DT producer to fetch all vulnerabilities from a specific project")
	flag.StringVar(&ProjectID, "projectID", "", "only used with \"Fetch\", if fetch is defined, vulnerabilities of the specific projectID will be fetched")
	flag.StringVar(&APIKey, "apiKey", "", "only used with \"Fetch\", if fetch is defined, vulnerabilities of the specific projectID will be fetched using this API Key")
	flag.StringVar(&URL, "url", "", "only used with \"Fetch\", if fetch is defined, vulnerabilities of the specific projectID will be fetched using this URL and the supplied API Key")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	var inFile []byte
	if Fetch {
		input, err := readFromDependencyTrack(APIKey, URL, ProjectID)
		if err != nil {
			log.Fatal(err)
		}
		inFile = input
	} else {
		input, err := producers.ReadInFile()
		if err != nil {
			log.Fatal(err)
		}
		inFile = input
	}
	var results DependencyTrackOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues, err := parseIssues(&results)
	if err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteSmithyOut(
		"Dependency Track",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}
func readFromDependencyTrack(apiKey, url, projectID string) ([]byte, error) {
	client, err := dtrack.NewClient(url, dtrack.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("could not instantiate client err: %#v", err)
	}

	findings, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Finding], error) {
		return client.Finding.GetAll(context.Background(), uuid.MustParse(projectID), false, po)
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(findings)
}
func parseIssues(out *DependencyTrackOut) ([]*v1.Issue, error) {
	issues := []*v1.Issue{}
	for _, element := range *out {
		iss := v1.Issue{}
		target := element.Component.Purl
		iss.Target = target
		cwe := []int32{}
		for _, c := range element.Vulnerability.Cwes {
			cwe = append(cwe, int32(c.CweID))
		}
		iss.Type = element.Vulnerability.VulnID
		iss.Title = element.Vulnerability.Title
		if element.Vulnerability.CvssV3BaseScore != 0 {
			iss.Cvss = element.Vulnerability.CvssV3BaseScore
		}
		switch element.Vulnerability.Severity {
		case "CRITICAL":
			iss.Severity = v1.Severity_SEVERITY_CRITICAL
		case "HIGH":
			iss.Severity = v1.Severity_SEVERITY_HIGH

		case "MEDIUM":
			iss.Severity = v1.Severity_SEVERITY_MEDIUM
		case "LOW":
			iss.Severity = v1.Severity_SEVERITY_LOW
		case "INFO":
			iss.Severity = v1.Severity_SEVERITY_INFO
		case "UNASSIGNED":
			iss.Severity = v1.Severity_SEVERITY_UNSPECIFIED

		}
		iss.Cwe = cwe
		if len(element.Vulnerability.Aliases) > 0 {
			iss.Cve = element.Vulnerability.Aliases[0].CveID
		}
		iss.Description = fmt.Sprintf("%s\n%s", element.Vulnerability.Description, element.Vulnerability.Recommendation)
		if len(element.Vulnerability.Aliases) > 0 {
			iss.Description = fmt.Sprintf("%s\nVulnerability Aliases:", iss.Description)
			for _, alias := range element.Vulnerability.Aliases {
				serialised, err := json.Marshal(alias)
				if err != nil {
					log.Println("Error serialising vulnerability alias", alias, "skipping")
					continue
				}
				iss.Description = fmt.Sprintf("%s\n%s", iss.Description, string(serialised))
			}
		}
		issues = append(issues, &iss)
	}

	return issues, nil
}

// Aliases is DTs vulnerability aliases struct
type Aliases []struct {
	CveID  string `json:"cveId"`
	SnykID string `json:"snykId"`
}

// Component is a DT component
type Component struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Group         string `json:"group"`
	Version       string `json:"version"`
	Purl          string `json:"purl"`
	Project       string `json:"project"`
	LatestVersion string `json:"latestVersion"`
}

// Vulnerability is a DT Vulnerability for a single component
type Vulnerability struct {
	UUID            string  `json:"uuid"`
	Source          string  `json:"source"`
	VulnID          string  `json:"vulnId"`
	Title           string  `json:"title"`
	CvssV3BaseScore float64 `json:"cvssV3BaseScore"`
	Severity        string  `json:"severity"`
	SeverityRank    int     `json:"severityRank"`
	CweID           int     `json:"cweId"`
	CweName         string  `json:"cweName"`
	Cwes            []struct {
		CweID int    `json:"cweId"`
		Name  string `json:"name"`
	} `json:"cwes"`
	Aliases        Aliases `json:"aliases"`
	Description    string  `json:"description"`
	Recommendation string  `json:"recommendation"`
}

// DependencyTrackOut is an export from DT findings API
type DependencyTrackOut []struct {
	Component     Component     `json:"component"`
	Vulnerability Vulnerability `json:"vulnerability"`

	Analysis struct {
		IsSuppressed bool `json:"isSuppressed"`
	} `json:"analysis"`
	Attribution struct {
		AnalyzerIdentity string `json:"analyzerIdentity"`
		AttributedOn     int64  `json:"attributedOn"`
	} `json:"attribution"`
	Matrix string `json:"matrix"`
}
