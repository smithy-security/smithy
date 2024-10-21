package jira

import (
	"fmt"
	"io"
	"log"

	"github.com/andygrunwald/go-jira"

	"github.com/smithy-security/smithy/pkg/jira/config"
	"github.com/smithy-security/smithy/pkg/jira/document"
)

// Client is a wrapper of a go-jira client with our config on top.
type Client struct {
	JiraClient    *jira.Client
	DryRunMode    bool
	Config        config.Config
	DefaultFields defaultJiraFields
}

// NewClient returns a client containing the authentication details and the configuration settings.
func NewClient(user, token, url string, dryRun bool, config config.Config) *Client {
	return &Client{
		JiraClient:    authJiraClient(user, token, url),
		DryRunMode:    dryRun,
		Config:        config,
		DefaultFields: getDefaultFields(config),
	}
}

// authJiraClient authenticates the client with the given Username, API token, and URL domain.
func authJiraClient(user, token, url string) *jira.Client {
	tp := jira.BasicAuthTransport{
		Username: user,
		Password: token,
	}
	JiraClientlient, err := jira.NewClient(tp.Client(), url)
	if err != nil {
		log.Fatalf("Unable to contact Jira: %s", err)
	}
	return JiraClientlient
}

// assembleIssue parses the Smithy message and serializes it into a Jira Issue object.
func (c Client) assembleIssue(smithyResult document.Document) *jira.Issue {
	// Mappings the Smithy Result fields to their corresponding Jira fields specified in the configuration
	customFields := c.DefaultFields.CustomFields.Clone()

	for _, m := range c.Config.Mappings {
		strMap, _ := smithyResultToSTRMaps(smithyResult)
		if _, ok := smithyResult.Annotations[m.SmithyField]; ok {
			customFields[m.JiraField] = makeCustomField(m.FieldType, []string{smithyResult.Annotations[m.SmithyField]})
		} else {
			customFields[m.JiraField] = makeCustomField(m.FieldType, []string{strMap[m.SmithyField]})
		}
	}
	summary, extra := makeSummary(smithyResult)
	description := makeDescription(smithyResult, c.Config.DescriptionTemplate)
	if extra != "" {
		description = fmt.Sprintf(".... %s\n%s", extra, description)
	}
	iss := &jira.Issue{
		Fields: &jira.IssueFields{
			Project:     c.DefaultFields.Project,
			Type:        c.DefaultFields.IssueType,
			Description: description,
			Summary:     summary,
			Unknowns:    customFields,
		},
	}
	if len(c.DefaultFields.Components) != 0 {
		iss.Fields.Components = c.DefaultFields.Components
	}
	if len(c.DefaultFields.AffectsVersions) != 0 {
		iss.Fields.AffectsVersions = c.DefaultFields.AffectsVersions
	}
	if len(c.DefaultFields.Labels) != 0 {
		iss.Fields.Labels = c.DefaultFields.Labels
	}
	return iss
}

// CreateIssue creates a new issue in Jira.
func (c Client) CreateIssue(smithyResult document.Document) error {
	issue := c.assembleIssue(smithyResult)

	if c.DryRunMode {
		log.Printf("Dry run mode. The following issue would have been created: '%s'", issue.Fields.Summary)
		return nil
	}

	ri, resp, err := c.JiraClient.Issue.Create(issue)
	if err != nil {
		if resp != nil {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return fmt.Errorf("error while trying to create Jira ticket and error while trying to read response body: %w\n\n%w", err, readErr)
			}
			return fmt.Errorf("error while trying to create new Jira ticket %s: %w", string(body), err)
		} else {
			return fmt.Errorf("error while trying to create new Jira ticket: %w", err)
		}
	}
	log.Printf("Created Jira Issue ID %s. jira_key=%s", ri.ID, string(ri.Key))
	return nil
}

// SearchByJQL searches jira instance by JQL and returns results with history.
func (c Client) SearchByJQL(jql string) ([]jira.Issue, error) {
	var results []jira.Issue
	startAt := 0
	maxresults := 100
	expand := "names,schema,operations,editmeta,changelog,renderedFields"
	issues, response, err := c.JiraClient.Issue.Search(jql, &jira.SearchOptions{Expand: expand, StartAt: startAt, MaxResults: maxresults}) // maxresults is capped to 100 by attlasian
	if err != nil {
		log.Print(response)
		return nil, err
	}
	results = append(results, issues...)
	startAt = len(results)
	log.Print("The query returned ", response.Total, " results")
	for len(results) < response.Total {
		issues, response, err = c.JiraClient.Issue.Search(jql, &jira.SearchOptions{Expand: expand, StartAt: startAt, MaxResults: maxresults}) // maxresults is capped to 100 by attlasian
		if err != nil {
			log.Print(response)
			return nil, err
		}
		results = append(results, issues...)
		startAt = len(results)
	}
	return results, nil
}
