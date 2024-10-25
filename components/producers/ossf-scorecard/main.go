package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"

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
	slog.Info("read ", slog.Int("numChecks", len(out.Checks)))
	issues := []*v1.Issue{}
	repo := out.Repo.Name
	commit := out.Repo.Commit

	for _, r := range out.Checks {
		desc := fmt.Sprintf("Overall Score: %.1f\nCheck Details:\n", out.Score)

		for i, deet := range r.Details {
			d := deet
			if i != len(r.Details)-1 {
				d += "\n"
			}
			desc += d
		}
		issues = append(issues, &v1.Issue{
			Target:      fmt.Sprintf("%s:%s", repo, commit),
			Type:        r.Name,
			Title:       r.Reason,
			Severity:    scorecardToSmithySeverity(r.Score),
			Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: desc,
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
	Date      string        `json:"date,omitempty"`
	Repo      RepoInfo      `json:"repo,omitempty"`
	Scorecard ScorecardInfo `json:"scorecard,omitempty"`
	Score     float64       `json:"score,omitempty"`
	Checks    []Check       `json:"checks,omitempty"`
	Metadata  any           `json:"metadata,omitempty"`
}

// Check represents a ScoreCard Result.
type Check struct {
	Details       []string `json:"details,omitempty"`
	Score         float64  `json:"score,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Name          string   `json:"name,omitempty"`
	Documentation Docs     `json:"documentation,omitempty"`
}

// Docs represents a ScoreCard "docs" section.
type Docs struct {
	URL   string `json:"url,omitempty"`
	Short string `json:"short,omitempty"`
}

// ScorecardInfo represents a "scorecardinfo" section.
type ScorecardInfo struct {
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// RepoInfo represents a repository information section.
type RepoInfo struct {
	Name   string `json:"name,omitempty"`
	Commit string `json:"commit,omitempty"`
}
