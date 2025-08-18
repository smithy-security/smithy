package reporter

import (
	"bytes"
	_ "embed"
	"strings"
	"text/template"

	"github.com/go-errors/errors"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter/util"
)

//go:embed issue.tpl
var issueTpl string

type IssueData struct {
	Description      string
	Title            string
	FindingID        uint64
	FindingLink      string
	TargetName       string
	TargetLink       string
	IsRepository     bool
	IsPurl           bool
	Confidence       string
	CWE              string
	CWELink          string
	CVE              string
	Tool             string
	RunName          string
	RunLink          string
	FindingPath      string
	FindingStartLine uint32
	FindingEndLine   uint32
	Reference        string
}

func (r slackReporter) getMsgs(findings []*vf.VulnerabilityFinding) ([]string, error) {
	tpl, err := template.New("issue").Parse(issueTpl)
	if err != nil {
		return nil, errors.Errorf("could not parse thread template: %w", err)
	}

	const (
		unknownValue = "unknown"
		unsetValue   = "-"
	)

	var msgs []string
	for _, finding := range findings {
		var (
			findingPath, targetName, targetLink, reference, confidence = unknownValue, unknownValue, unknownValue, unknownValue, unknownValue
			findingStartLine, findingEndLine                           uint32
			isRepository, isPurl                                       bool
		)

		if finding.Finding.GetConfidence() != "" {
			confidence = r.getConfidence(finding.Finding.GetConfidenceId())
		}

		if len(finding.Finding.GetFindingInfo().DataSources) > 0 {
			var dataSource ocsffindinginfo.DataSource
			if err := protojson.Unmarshal([]byte(finding.Finding.GetFindingInfo().DataSources[0]), &dataSource); err != nil {
				return nil, errors.Errorf("could not unmarshal finding data source from finding info: %w", err)
			}

			if dataSource.GetTargetType() == ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY {
				reference = dataSource.GetSourceCodeMetadata().GetReference()

				switch dataSource.GetUri().GetUriSchema() {
				case ocsffindinginfo.DataSource_URI_SCHEMA_FILE:
					isRepository = true
					findingStartLine = dataSource.GetFileFindingLocationData().GetStartLine()
					findingEndLine = dataSource.GetFileFindingLocationData().GetEndLine()
					findingPath = dataSource.GetUri().GetPath()
					targetName = dataSource.GetSourceCodeMetadata().GetRepositoryUrl()
					var err error
					targetLink, err = util.MakeRepositoryLink(&dataSource)
					if err != nil {
						return nil, errors.Errorf("could not get repo target link: %w", err)
					}
				case ocsffindinginfo.DataSource_URI_SCHEMA_PURL:
					isPurl = true
					targetName = dataSource.GetPurlFindingLocationData().String()
					targetLink = dataSource.GetPurlFindingLocationData().String()
					findingPath = dataSource.GetPurlFindingLocationData().String()
				}
			}
		}

		targetName = strings.TrimPrefix(targetLink, "https://")

		for _, f := range finding.Finding.GetVulnerabilities() {
			var (
				findingLink = util.MakeFindingLink(
					r.conf.SmithyDashURL.Host,
					finding.ID,
				)
				runLink = util.MakeRunLink(
					r.conf.SmithyDashURL.Host,
					r.conf.SmithyInstanceID,
				)
				tool, cwe, cweLink, cve = unknownValue, unsetValue, unsetValue, unsetValue
			)

			if f.GetVendorName() != "" {
				tool = f.GetVendorName()
			}

			if f.GetCwe().GetCaption() != "" {
				cwe = f.GetCwe().GetCaption()
			}

			if f.GetCwe().GetSrcUrl() != "" {
				cweLink = f.GetCwe().GetSrcUrl()
			}

			if f.GetCve().GetUid() != "" {
				cve = f.GetCve().GetUid()
			}

			var buf bytes.Buffer
			if err := tpl.Execute(
				&buf,
				IssueData{
					Title:            f.GetTitle(),
					Description:      f.GetDesc(),
					FindingID:        finding.ID,
					FindingLink:      findingLink,
					Tool:             tool,
					TargetLink:       targetLink,
					TargetName:       targetName,
					IsRepository:     isRepository,
					IsPurl:           isPurl,
					Confidence:       confidence,
					CWE:              cwe,
					CWELink:          cweLink,
					CVE:              cve,
					RunName:          r.conf.SmithyInstanceName,
					RunLink:          runLink,
					FindingPath:      findingPath,
					FindingStartLine: findingStartLine,
					FindingEndLine:   findingEndLine,
					Reference:        reference,
				},
			); err != nil {
				return nil, errors.Errorf("could not execute issue description template: %w", err)
			}

			msgs = append(msgs, buf.String())
		}
	}

	return msgs, nil
}

func (r slackReporter) getPriority(severity string) string {
	switch severity {
	case ocsf.VulnerabilityFinding_SEVERITY_ID_LOW.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER.String():
		return "Low"
	case ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String():
		return "Medium"
	case ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String():
		return "High"
	case ocsf.VulnerabilityFinding_SEVERITY_ID_FATAL.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String():
		return "Highest"
	}
	return severity
}

func (r slackReporter) getConfidence(confidence ocsf.VulnerabilityFinding_ConfidenceId) string {
	switch confidence {
	case ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW,
		ocsf.VulnerabilityFinding_CONFIDENCE_ID_OTHER:
		return "Low"
	case ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM:
		return "Medium"
	case ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH:
		return "High"
	}
	return "Unknown"
}
