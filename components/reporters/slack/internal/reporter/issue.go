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

const (
	unknownValue = "unknown"
	unsetValue   = "-"
)

// IssueData holds all the information needed to create a Slack issue message from a VulnerabilityFinding and Vulnerability instance.
// It is designed to be used with text/template to generate formatted messages.
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
	Priority         string
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

// NewIssueData creates a new IssueData struct from a VulnerabilityFinding and configuration.
// It sets default values for most of the IssueData fields, and extracts relevant information for elements that are common across vulns from a single scan (e.g. time started or runID)
func NewIssueData(finding *vf.VulnerabilityFinding, conf *Conf) (*IssueData, error) {
	if finding == nil || finding.Finding == nil {
		return nil, errors.New("finding or finding.Finding is nil")
	}

	if conf == nil {
		return nil, errors.New("configuration is nil")
	}

	var (
		findingPath, targetLink, reference, confidence, severity, title, description = unknownValue, unknownValue, unknownValue, unknownValue, unknownValue, unsetValue, unsetValue
		findingStartLine, findingEndLine                                             uint32
		isRepository, isPurl                                                         bool
		findingLink                                                                  = util.MakeFindingLink(conf.SmithyDashURL.Host, finding.ID)
		runLink                                                                      = util.MakeRunLink(conf.SmithyDashURL.Host, conf.SmithyInstanceID)
	)

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
				var err error
				targetLink, err = util.MakeRepositoryLink(&dataSource)
				if err != nil {
					return nil, errors.Errorf("could not get repo target link: %w", err)
				}
			case ocsffindinginfo.DataSource_URI_SCHEMA_PURL:
				isPurl = true
				targetLink = dataSource.GetPurlFindingLocationData().String()
				findingPath = dataSource.GetPurlFindingLocationData().String()
			default:
				return nil, errors.Errorf("unsupported data source uri schema: %s", dataSource.GetUri().GetUriSchema().String())
			}

		}
	}

	issueData := &IssueData{
		FindingID:        finding.ID,
		FindingLink:      findingLink,
		TargetLink:       targetLink,
		TargetName:       strings.TrimPrefix(targetLink, "https://"),
		IsRepository:     isRepository,
		IsPurl:           isPurl,
		Confidence:       confidence,
		RunName:          conf.SmithyInstanceName,
		RunLink:          runLink,
		FindingPath:      findingPath,
		FindingStartLine: findingStartLine,
		FindingEndLine:   findingEndLine,
		Reference:        reference,
		Priority:         severity,
		Title:            title,
		Description:      description,
	}

	if finding.Finding.GetConfidence() != "" {
		issueData.Confidence = issueData.getConfidence(finding.Finding.GetConfidenceId())
	}

	// Set default, overridable values for Priority and Description
	if finding.Finding.GetSeverity() != "" {
		issueData.Priority = issueData.getPriority(finding.Finding.GetSeverity())
	}

	if finding.Finding.GetMessage() != "" {
		issueData.Description = finding.Finding.GetMessage()
	}

	return issueData, nil
}

// NewVulnerability enriches the current IssueData with a new Vulnerability instance from the IssueData.
// It sets default values for Tool, CWE, CWELink, and CVE, and extracts relevant information from the Vulnerability instance to populate the IssueData fields.
// It overrides Title, Description, and Priority fields if the Vulnerability instance provides values for them.
func (i IssueData) EnrichWithNewVulnerability(vulnerability *ocsf.Vulnerability) (*IssueData, error) {

	i.Tool, i.CWE, i.CWELink, i.CVE = unknownValue, unsetValue, unsetValue, unsetValue

	if vulnerability.GetVendorName() != "" {
		i.Tool = vulnerability.GetVendorName()
	}

	if vulnerability.GetCwe().GetCaption() != "" {
		i.CWE = vulnerability.GetCwe().GetCaption()
	}

	if vulnerability.GetCwe().GetSrcUrl() != "" {
		i.CWELink = vulnerability.GetCwe().GetSrcUrl()
	}

	if vulnerability.GetCve().GetUid() != "" {
		i.CVE = vulnerability.GetCve().GetUid()
	}

	// Override Title, Description, and Priority if the vulnerability provides them
	if vulnerability.GetSeverity() != "" {
		i.Priority = i.getPriority(vulnerability.GetSeverity())
	}

	if vulnerability.GetDesc() != "" {
		i.Description = vulnerability.GetDesc()
	}

	if vulnerability.GetTitle() != "" {
		i.Title = vulnerability.GetTitle()
	}

	return &i, nil
}

// String executes the provided template with the IssueData and returns the resulting string.
func (i IssueData) String(tpl *template.Template) (string, error) {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, i); err != nil {
		return "", errors.Errorf("could not execute issue description template: %w", err)
	}
	return buf.String(), nil
}

func (i IssueData) getPriority(severity string) string {
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

func (i IssueData) getConfidence(confidence ocsf.VulnerabilityFinding_ConfidenceId) string {
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
