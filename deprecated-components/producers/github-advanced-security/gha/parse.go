package gha

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/go-github/v69/github"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
)

func ParseIssues(alerts []*github.Alert) []*v1proto.Issue {
	issues := make([]*v1proto.Issue, 0, len(alerts))
	for _, alert := range alerts {
		issue := &v1proto.Issue{
			Target: producers.GetFileTarget(
				alert.GetMostRecentInstance().GetLocation().GetPath(),
				alert.GetMostRecentInstance().GetLocation().GetStartLine(),
				alert.GetMostRecentInstance().GetLocation().GetEndLine(),
			),
			Type:        strconv.Itoa(alert.GetNumber()),
			Title:       *alert.GetRule().Description,
			Severity:    parseGitHubSeverity(*alert.GetRule().Severity),
			Cvss:        0,
			Confidence:  v1proto.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: alert.GetMostRecentInstance().GetMessage().GetText(),
			Source:      alert.GetHTMLURL(),
			Cwe:         parseGithubCWEsFromTags(alert.Rule.Tags),
		}
		issues = append(issues, issue)
	}

	return issues
}

func parseGitHubSeverity(severity string) v1proto.Severity {
	switch severity {
	case "low":
		return v1proto.Severity_SEVERITY_LOW
	case "medium":
		return v1proto.Severity_SEVERITY_MEDIUM
	case "high":
		return v1proto.Severity_SEVERITY_HIGH
	case "critical":
		return v1proto.Severity_SEVERITY_CRITICAL
	default:
		return v1proto.Severity_SEVERITY_UNSPECIFIED
	}
}

func parseGithubCWEsFromTags(tags []string) []int32 {
	// example input: ["security", "external/cwe/cwe-022"]
	cwePrefix := "external/cwe/cwe-"

	cwes := make([]int32, 0, len(tags))
	for _, item := range tags {
		if strings.HasPrefix(item, cwePrefix) {
			cweString := strings.TrimPrefix(item, cwePrefix)

			cwe, err := strconv.ParseInt(cweString, 10, 32)
			if err != nil {
				slog.Warn("Failed to parse CWE from tag", slog.String("tag", item), slog.Any("error", err))
				continue
			}
			cwes = append(cwes, int32(cwe))
		}
	}
	return cwes
}
