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

	var results ScorecardOut
	if err := json.Unmarshal(inFile, &results); err != nil {
		log.Fatal(err)
	}

	issues := parseIssues(&results)

	if err := producers.WriteSmithyOut(
		"scorecard",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func parseIssues(out *ScorecardOut) []*v1.Issue {
	issues := []*v1.Issue{}
	repo := out.Repo.Name
	commit := out.Repo.Commit
	for _, r := range out.Checks {
		desc, _ := json.Marshal(r)
		issues = append(issues, &v1.Issue{
			Target:      fmt.Sprintf("%s:%s", repo, commit),
			Type:        r.Name,
			Title:       r.Reason,
			Severity:    scorecardToSmithySeverity(r.Score),
			Cvss:        0.0,
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: string(desc),
		})
	}
	return issues
}

func scorecardToSmithySeverity(score float64) v1.Severity {
	switch {
	case score < 0:
		return v1.Severity_SEVERITY_UNSPECIFIED
	case 0 <= score && score < 3:
		return v1.Severity_SEVERITY_INFO
	case 3 <= score && score < 5:
		return v1.Severity_SEVERITY_LOW
	case 5 <= score && score < 7:
		return v1.Severity_SEVERITY_MEDIUM
	case 7 <= score && score < 9:
		return v1.Severity_SEVERITY_HIGH
	}
	return v1.Severity_SEVERITY_CRITICAL
}

// ScorecardOut represents the output of a ScoreCard run.
type ScorecardOut struct {
	Date      string
	Repo      RepoInfo
	Scorecard ScorecardInfo
	Score     float64
	Checks    []Check `json:"checks"`
}

// Check represents a ScoreCard Result.
type Check struct {
	Details       []string
	Score         float64
	Reason        string
	Name          string
	Documentation Docs
}

// Docs represents a ScoreCard "docs" section.
type Docs struct {
	URL   string
	Short string
}

// ScorecardInfo represents a "scorecardinfo" section.
type ScorecardInfo struct {
	Version string
	Commit  string
}

// RepoInfo represents a repository information section.
type RepoInfo struct {
	Name   string
	Commit string
}
