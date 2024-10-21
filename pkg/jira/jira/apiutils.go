package jira

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andygrunwald/go-jira"
	"github.com/trivago/tgo/tcontainer"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/enumtransformers"
	"github.com/smithy-security/smithy/pkg/jira/config"
	"github.com/smithy-security/smithy/pkg/jira/document"
	"github.com/smithy-security/smithy/pkg/templating"
)

type defaultJiraFields struct {
	Project         jira.Project
	IssueType       jira.IssueType
	Components      []*jira.Component
	AffectsVersions []*jira.AffectsVersion
	Labels          []string
	CustomFields    tcontainer.MarshalMap
}

//go:embed issueTemplate.txt
var defaultTemplate string

// getDefaultFields creates the fields for Project, IssueType, Components, AffectsVersions, Labels and CustomFields
// with the default values specified in config.yaml and serializes them into Jira Fields.
func getDefaultFields(config config.Config) defaultJiraFields {
	defaultFields := defaultJiraFields{}
	defaultFields.Project = jira.Project{
		Key: config.DefaultValues.Project,
	}

	defaultFields.IssueType = jira.IssueType{
		Name: config.DefaultValues.IssueType,
	}

	components := []*jira.Component{}
	for _, v := range config.DefaultValues.Components {
		components = append(components, &jira.Component{Name: v})
	}
	defaultFields.Components = components

	affectsVersions := []*jira.AffectsVersion{}
	for _, v := range config.DefaultValues.AffectsVersions {
		affectsVersions = append(affectsVersions, &jira.AffectsVersion{Name: v})
	}
	defaultFields.AffectsVersions = affectsVersions

	defaultFields.Labels = config.DefaultValues.Labels

	customFields := tcontainer.NewMarshalMap()
	for _, cf := range config.DefaultValues.CustomFields {
		customFields[cf.ID] = makeCustomField(cf.FieldType, cf.Values)
	}
	defaultFields.CustomFields = customFields

	return defaultFields
}

// makeCustomField returns the appropriate interface for a jira CustomField given it's type and values
// :param fieldType: the type of the field in Jira (single-value, multi-value, float)
// :param values: list of values to be filled in
// :return the appropriate interface for a CustomField, given the corresponding fieldType and value(s).
func makeCustomField(fieldType string, values []string) interface{} {
	switch fieldType {
	case "single-value":
		return map[string]string{"value": values[0]}
	case "multi-value":
		cf := []map[string]string{}
		for _, v := range values {
			cf = append(cf, map[string]string{"value": v})
		}
		return cf
	case "float":
		f, err := strconv.ParseFloat(values[0], 64)
		if err != nil {
			log.Fatalf("Error parsing float field-type: %v", err)
		}
		return f
	case "simple-value":
		return values[0]
	default:
		log.Printf("Warning: Field type %s is not supported. Edit your config.yaml file, as this field will not be displayed correctly.", fieldType)
		return nil
	}
}

func smithyResultToSTRMaps(smithyResult document.Document) (map[string]string, string) {
	var strMap map[string]string

	annotations, err := json.Marshal(smithyResult.Annotations)
	if err != nil {
		log.Fatalf("could not marshal annotations: %s", err)
	}
	smithyResult.Annotations = nil
	tmp, err := json.Marshal(smithyResult)
	if err != nil {
		log.Fatalf("could not marshal result: %s", err)
	}
	if err := json.Unmarshal(tmp, &strMap); err != nil {
		log.Fatalf("could not unmarshal result: %s", err)
	}
	return strMap, string(annotations)
}

// makeDescription creates the description of an issue's enhanced with extra information from the Smithy Result.
func makeDescription(smithyResult document.Document, template string) string {

	if template == "" {
		template = defaultTemplate
	}
	if smithyResult.Count == "" {
		smithyResult.Count = "0"
	}
	count, err := strconv.Atoi(smithyResult.Count)
	if err != nil {
		log.Fatal("could not template enriched issue ", err)
	}
	fp := false
	if strings.ToLower(smithyResult.FalsePositive) == "true" {
		fp = true
	}
	if smithyResult.CVSS == "" {
		smithyResult.CVSS = "0.0"
	}
	cvss, err := strconv.ParseFloat(smithyResult.CVSS, 64)
	if err != nil {
		log.Fatal("could not template enriched issue ", err)
	}

	description, err := templating.TemplateStringEnriched(template,
		&v1.EnrichedIssue{
			Annotations:   smithyResult.Annotations,
			Count:         uint64(count),
			FalsePositive: fp,
			FirstSeen:     timestamppb.New(smithyResult.FirstFound),
			Hash:          smithyResult.Hash,
			RawIssue: &v1.Issue{
				Confidence:  enumtransformers.TextToConfidence(smithyResult.ConfidenceText),
				Cve:         smithyResult.CVE,
				Cvss:        cvss,
				Description: smithyResult.Description,
				Severity:    enumtransformers.TextToSeverity(smithyResult.SeverityText),
				Source:      smithyResult.Source,
				Target:      smithyResult.Target,
				Title:       smithyResult.Title,
				Type:        smithyResult.Type,
			},
		},
		templating.EnrichedIssueWithToolName(smithyResult.ToolName),
		templating.EnrichedIssueWithScanID(smithyResult.ScanID),
		templating.EnrichedIssueWithConfidenceText(smithyResult.ConfidenceText),
		templating.EnrichedIssueWithCount(uint(count)),
		templating.EnrichedIssueWithSeverityText(smithyResult.SeverityText),
	)
	if err != nil {
		log.Fatal("Could not template enriched issue ", err)
	}
	desc := *description
	return desc
}

// makeSummary creates the Summary/Title of an issue.
func makeSummary(smithyResult document.Document) (string, string) {
	summary := filepath.Base(smithyResult.Target) + " " + smithyResult.Title

	if len(summary) > 255 { // jira summary field supports up to 255 chars
		tobytes := bytes.Runes([]byte(summary))
		summary = string(tobytes[:254])
		extra := string(tobytes[255:])
		return summary, extra
	}
	return summary, ""
}
