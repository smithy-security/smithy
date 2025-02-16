package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/components/producers/github-advanced-security/gha"
)

// LookupEnvOrString will return the value of the environment variable
// if it exists, otherwise it will return the default value.
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func main() {
	clientConfig := &gha.ClientConfig{}

	flag.StringVar(&clientConfig.RepositoryOwner, "repository-owner", "", "The owner of the GitHub repository")
	flag.StringVar(&clientConfig.RepositoryName, "repository-name", "", "The name of the GitHub repository")
	flag.StringVar(&clientConfig.Token, "token", "", "The GitHub token used to authenticate with the API")
	flag.StringVar(&clientConfig.Toolname, "toolname", "", "The tool to fetch results for. Leave empty for all tools")
	flag.StringVar(&clientConfig.Ref, "reference", "", "The Ref/branch to get alerts for")
	flag.StringVar(&clientConfig.Severity, "severity", "", "If specified, only code scanning alerts with this severity will be returned. Possible values are: critical, high, medium, low, warning, note, error")
	flag.StringVar(&clientConfig.RequestTimeoutStr, "request-timeout", LookupEnvOrString("GITHUB_CLIENT_REQUEST_TIMEOUT", "5m"), "how long to wait for all requests to finish")
	flag.StringVar(&clientConfig.PageSizeStr, "page-size", LookupEnvOrString("GITHUB_CLIENT_LIST_PAGE_SIZE", "100"), "page size for github (max 100)")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	err := clientConfig.Parse()
	if err != nil {
		log.Fatal("could not parse configuration: " + err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientConfig.RequestTimeout)
	defer cancel()

	apiClient := gha.NewClient(ctx, clientConfig)
	res, err := apiClient.ListRepoAlerts(ctx)
	if err != nil {
		log.Fatalf("error while querying API: %s", err.Error())
	}

	if err := producers.WriteSmithyOut(
		"github-advanced-security",
		gha.ParseIssues(res),
	); err != nil {
		log.Fatal(err)
	}
}
