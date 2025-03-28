package main

import (
	"flag"
	"log"
	"os"

	"github.com/smithy-security/smithy/deprecated-components/consumers"

	"github.com/smithy-security/smithy/deprecated-components/consumers/jira/utils"
	"github.com/smithy-security/smithy/pkg/jira/config"
	"github.com/smithy-security/smithy/pkg/jira/jira"
)

const (
	// EnvJiraUser the Jira Username for the authentication (user@domain.com).
	EnvJiraUser = "SMITHY_JIRA_USER"
	// EnvJiraToken the Jira API token for the authentication.
	//nolint:gosec
	EnvJiraToken = "SMITHY_JIRA_TOKEN"
	// EnvJiraURL the domain to scrape.
	EnvJiraURL = "SMITHY_JIRA_URL"
	// EnvConfigPath the path towards the config.yaml file.
	EnvConfigPath = "SMITHY_JIRA_CONFIG_PATH"
)

var (
	authUser          string
	authToken         string
	jiraURL           string
	dryRunMode        bool
	allowDuplicates   bool
	allowFP           bool
	severityThreshold int
	failOnError       bool
)

func init() {
	authUser = os.Getenv(EnvJiraUser)
	authToken = os.Getenv(EnvJiraToken)
	jiraURL = os.Getenv(EnvJiraURL)
	flag.BoolVar(&dryRunMode, "dry-run", false, "Dry run. Tickets will not be created.")
	flag.BoolVar(&allowDuplicates, "allow-duplicates", false, "Allow duplicate issues to be created.")
	flag.BoolVar(&allowFP, "allow-fp", false, "Allow issues tagged as 'false positive' to be created.")
	flag.BoolVar(&failOnError, "fail-on-error", false, "Fail immediately if any issue fails to be created on jira")
	flag.IntVar(&severityThreshold, "severity-threshold", 3, "Only issues equal or above this threshold will get processed. Must be one of: {0: Info, 1: Minor / Localized, 2: Moderate / Limited, 3: Significant / Large, 4: Extensive / Widespread}")
}

func main() {
	// Parse consumer flags
	if err := consumers.ParseFlags(); err != nil {
		log.Fatal("Could not parse flags: ", err)
	}

	// Parse config.yaml
	file, err := os.Open(os.Getenv(EnvConfigPath))
	if err != nil {
		log.Fatalf("Could not open config file:   #%v ", err)
	}
	config, err := config.New(file)
	if err != nil {
		log.Fatalf("Could not parse config file: %v", err)
	}

	// Authenticate Jira client
	apiClient := jira.NewClient(authUser, authToken, jiraURL, dryRunMode, config)

	// Parse Smithy results
	smithyResults, discardedIssues, err := utils.ProcessMessages(allowDuplicates, allowFP, severityThreshold)
	if err != nil {
		log.Fatalf("Could not process messages: %s", err)
	}

	// Create issues in Jira
	createdIssues := 0
	failedIssues := 0
	for _, result := range smithyResults {
		if err := apiClient.CreateIssue(result); err != nil {
			failedIssues++
			if failOnError {
				log.Fatalf("error creating jira issue err: %#v\n", err.Error())
			}
			log.Printf("error creating jira issue err: %#v\n", err.Error())
		} else {
			createdIssues++
		}
	}

	// Output metrics
	log.Printf("%d Issues have been discarded as duplicates or false positives\n", discardedIssues)
	log.Printf("Smithy results: %d; Created issues: %d; Issues failed to create: %d\n", len(smithyResults), createdIssues, failedIssues)
	if failedIssues > 0 {
		os.Exit(1)
	}
}
