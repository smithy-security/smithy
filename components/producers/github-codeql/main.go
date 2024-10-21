package main

import (
	"context"
	"flag"
	"io"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/google/go-github/v65/github"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	wrapper "github.com/smithy-security/smithy/pkg/github"
)

type config struct {
	// RepositoryOwner is the owner of the GitHub repository
	RepositoryOwner string

	// RepositoryName is the name of the GitHub repository
	RepositoryName string

	// GitHubToken is the GitHub token used to authenticate
	GitHubToken string

	// Ref is the Ref/branch to get alerts for
	Ref string

	// Severity if specified, only code scanning alerts with this severity will be returned. Possible values are: critical, high, medium, low, warning, note, error
	Severity string

	// toolName is internal
	toolName string

	// RequestTimeout is how long to wait for github to respond
	RequestTimeout string

	requestTimeout time.Duration

	// ClientListPageSize is how many alerts to ask from github at once (max 100)
	ClientListPageSize string
	clientListPageSize int
}

var cfg config

// LookupEnvOrString will return the value of the environment variable
// if it exists, otherwise it will return the default value.
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func main() {
	flag.StringVar(&cfg.RepositoryOwner, "repository-owner", "", "The owner of the GitHub repository")
	flag.StringVar(&cfg.RepositoryName, "repository-name", "", "The name of the GitHub repository")
	flag.StringVar(&cfg.GitHubToken, "github-token", "", "The GitHub token used to authenticate with the API")
	flag.StringVar(&cfg.Ref, "reference", "", "The Ref/branch to get alerts for")
	flag.StringVar(&cfg.Severity, "severity", "", "If specified, only code scanning alerts with this severity will be returned. Possible values are: critical, high, medium, low, warning, note, error")
	flag.StringVar(&cfg.RequestTimeout, "request-timeout", LookupEnvOrString("GITHUB_CLIENT_REQUEST_TIMEOUT", "5m"), "how long to wait for all requests to finish")
	flag.StringVar(&cfg.ClientListPageSize, "list-page-size", LookupEnvOrString("GITHUB_CLIENT_LIST_PAGE_SIZE", "100"), "page size for github (max 100)")
	cfg.toolName = "CodeQL"
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	duration, err := time.ParseDuration(cfg.RequestTimeout)
	if err != nil {
		log.Fatal(err)
	}
	cfg.requestTimeout = duration

	pageSize, err := strconv.Atoi(cfg.ClientListPageSize)
	if err != nil {
		log.Fatal(err)
	}
	cfg.clientListPageSize = pageSize

	apiClient := wrapper.NewClient(cfg.GitHubToken)
	alerts, err := listAlertsForRepo(ctx, apiClient, cfg.RepositoryOwner, cfg.RepositoryName, cfg.toolName, cfg.Severity)
	if err != nil {
		log.Fatal(err)
	}

	issues := parseIssues(alerts)

	if err := producers.WriteSmithyOut(
		"github-code-scanning",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func doCall(ctx context.Context, apiClient wrapper.Wrapper, owner, repo string, opt *github.AlertListOptions) ([]*github.Alert, *github.Response, error) {
	alerts, resp, err := apiClient.ListRepoAlerts(ctx, owner, repo, opt)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, bodyReadErr := io.ReadAll(resp.Body)
		if bodyReadErr != nil {
			return nil, nil, errors.Errorf("could not read response error from github, err:%w", bodyReadErr)
		}
		slog.Error("github response", slog.String("body", string(body)))
		return nil, nil, errors.Errorf("did not receive a valid status code from github, status code: %d, body:%s", resp.StatusCode, string(body))
	}
	return alerts, resp, nil
}

func listAlertsForRepo(ctx context.Context, apiClient wrapper.Wrapper, owner, repo, toolName, severity string) ([]*github.Alert, error) {
	var allAlerts []*github.Alert
	ctx, cancel := context.WithTimeout(ctx, cfg.requestTimeout)
	defer cancel()

	opt := &github.AlertListOptions{
		State:    "open",
		Ref:      cfg.Ref,
		Severity: severity,
		ToolName: toolName,
		ListOptions: github.ListOptions{
			PerPage: cfg.clientListPageSize,
		},
	}

	for {
		alerts, resp, err := doCall(ctx, apiClient, owner, repo, opt)
		if err != nil {
			return nil, err
		}

		allAlerts = append(allAlerts, alerts...)
		if resp.NextPage == 0 {
			break
		}

		opt.ListOptions.Page = resp.NextPage
	}

	slog.Info("Successfully fetched alerts", "count", len(allAlerts), "repository", owner+"/"+repo)
	return allAlerts, nil
}

func parseIssues(alerts []*github.Alert) []*v1proto.Issue {
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

			cwe, err := strconv.Atoi(cweString)
			if err != nil {
				slog.Warn("Failed to parse CWE from tag", slog.String("tag", item), slog.Any("error", err))
				continue
			}
			cwes = append(cwes, int32(cwe))
		}
	}
	return cwes
}
