// Package templating includes helper methods that apply
// go templates to Smithy Raw and Enriched Issues and return the resulting str
package templating

import (
	"bytes"
	"text/template"
	"time"

	"github.com/go-errors/errors"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

const (
	defaultEnrichedFindingTemplate = "Smithy found '{{.RawIssue.Title}}' at '{{.RawIssue.Target}}', severity '{{.RawIssue.Severity}}', rule id: '{{.RawIssue.Type}}', CVSS '{{.RawIssue.Cvss}}' Confidence '{{.RawIssue.Confidence}}' Original Description: {{.RawIssue.Description}}, Cve {{.RawIssue.Cve}},\n{{ range $key,$element := .Annotations }}{{$key}}:{{$element}}\n{{end}}"
	defaultRawFindingTemplate      = "Smithy found '{{.Title}}' at '{{.Target}}', severity '{{.Severity}}', rule id: '{{.Type}}', CVSS '{{.Cvss}}' Confidence '{{.Confidence}}' Original Description: {{.Description}}, Cve {{.Cve}}"
)

type (
	enrichedIssue struct {
		*v1.EnrichedIssue
		ToolName            string
		ScanStartTime       string
		ScanID              string
		ConfidenceText      string
		SeverityText        string
		Count               uint
		FirstFound          string
		FixedCodeAnnotation string
	}

	enrichedIssueOption func(*enrichedIssue) error
)

// TemplateStringRaw applies the provided go template to the Raw Issue provided and returns the resulting str
func TemplateStringRaw(inputTemplate string, issue *v1.Issue) (*string, error) {
	if inputTemplate == "" {
		inputTemplate = defaultRawFindingTemplate
	}
	tmpl, err := template.New("description").Parse(inputTemplate)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)

	err = tmpl.Execute(buf, issue)
	if err != nil {
		return nil, err
	}
	res := buf.String()
	return &res, nil
}

// EnrichedIssueWithToolName allows customising the Enriched Issue's ToolName.
func EnrichedIssueWithToolName(toolname string) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if toolname == "" {
			return errors.New("invalid toolname ''")
		}
		ei.ToolName = toolname
		return nil
	}
}

// EnrichedIssueWithConfidenceText allows customising the Enriched Issue's ConfidenceText.
func EnrichedIssueWithConfidenceText(confidence string) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if confidence == "" {
			return errors.New("invalid confidence ''")
		}
		ei.ConfidenceText = confidence
		return nil
	}
}

// EnrichedIssueWithSeverityText allows customising the Enriched Issue's SeverityText.
func EnrichedIssueWithSeverityText(severity string) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if severity == "" {
			return errors.New("invalid severity ''")
		}
		ei.SeverityText = severity
		return nil
	}
}

// EnrichedIssueWithCount allows customising the Enriched Issue's Count.
func EnrichedIssueWithCount(count uint) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		ei.Count = count
		return nil
	}
}

// EnrichedIssueWithScanID allows customising the Enriched Issue's Scan ID.
func EnrichedIssueWithScanID(scanID string) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if scanID == "" {
			return errors.New("invalid scanID ")
		}
		ei.ScanID = scanID
		return nil
	}
}

// EnrichedIssueWithScanStartTime allows customising the Enriched Issue's Scan start time.
func EnrichedIssueWithScanStartTime(startTime time.Time) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if startTime.IsZero() {
			return errors.Errorf("invalid startTime zero: %s", startTime.String())
		}
		ei.ScanStartTime = startTime.Format(time.RFC3339)
		return nil
	}
}

// EnrichedIssueWithFirstFound allows customising the Enriched Issue's Scan first found time.
func EnrichedIssueWithFirstFound(firstFound time.Time) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		if firstFound.IsZero() {
			return errors.Errorf("invalid firstFound zero %s", firstFound.String())
		}
		ff := firstFound.Format(time.RFC3339)
		ei.FirstFound = ff
		return nil
	}
}

// EnrichedIssueWithFixedCodeAnnotation allows to define which of the annotations contains fixed code
func EnrichedIssueWithFixedCodeAnnotation(fixedCodeAnnotation string) enrichedIssueOption {
	return func(ei *enrichedIssue) error {
		ei.FixedCodeAnnotation = fixedCodeAnnotation
		return nil
	}
}

// TemplateStringEnriched applies the provided go template to the Enriched Issue provided and returns the resulting str
func TemplateStringEnriched(inputTemplate string, issue *v1.EnrichedIssue, opts ...enrichedIssueOption) (*string, error) {
	enrichedIssue := &enrichedIssue{
		EnrichedIssue: issue,
	}
	for _, opt := range opts {
		if err := opt(enrichedIssue); err != nil {
			return nil, errors.Errorf("could not apply enriched issue option: %w", err)
		}
	}
	if inputTemplate == "" {
		inputTemplate = defaultEnrichedFindingTemplate
	}
	tmpl, err := template.New("description").Parse(inputTemplate)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)

	err = tmpl.Execute(buf, enrichedIssue)
	if err != nil {
		return nil, err
	}
	res := buf.String()
	return &res, nil
}
