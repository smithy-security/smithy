package reporter

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"text/template"

	"github.com/go-errors/errors"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
)

// IssueTplData is the template payload data used to build the description of the issue.
type IssueTplData struct {
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

func (r *reporter) getIssueRequests(tpl *template.Template, vf *vf.VulnerabilityFinding) ([]linear.CreateIssueRequest, error) {
	const (
		unknownValue = "unknown"
		unsetValue   = "-"
	)

	var (
		findingPath, targetName, targetLink, reference, confidence = unknownValue, unknownValue, unknownValue, unknownValue, unknownValue
		findingStartLine, findingEndLine                           uint32
		isRepository, isPurl                                       bool
	)

	if vf.Finding.GetConfidence() != "" {
		confidence = r.getConfidence(vf.Finding.GetConfidenceId())
	}

	if len(vf.Finding.GetFindingInfo().DataSources) > 0 {
		var dataSource ocsffindinginfo.DataSource
		if err := protojson.Unmarshal([]byte(vf.Finding.GetFindingInfo().DataSources[0]), &dataSource); err != nil {
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
				targetLink, err = r.getRepoTargetLink(&dataSource)
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

	var issues = make([]linear.CreateIssueRequest, 0, len(vf.Finding.GetVulnerabilities()))
	for _, f := range vf.Finding.GetVulnerabilities() {
		var (
			findingLink = fmt.Sprintf(
				"https://%s",
				path.Join(
					r.cfg.SmithyDashURL.Host,
					"issues",
					strconv.Itoa(int(vf.ID)),
				),
			)
			runLink = fmt.Sprintf(
				"https://%s",
				path.Join(
					r.cfg.SmithyDashURL.Host,
					"runs",
					r.cfg.SmithyInstanceID,
				),
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
			IssueTplData{
				FindingID:        vf.ID,
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
				RunName:          r.cfg.SmithyInstanceName,
				RunLink:          runLink,
				FindingPath:      findingPath,
				FindingStartLine: findingStartLine,
				FindingEndLine:   findingEndLine,
				Reference:        reference,
			},
		); err != nil {
			return nil, errors.Errorf("could not execute issue description template: %w", err)
		}

		issues = append(issues, linear.CreateIssueRequest{
			Description: buf.String(),
			Title:       f.GetTitle(),
			Priority:    r.getPriority(f.GetSeverity()),
		})
	}

	return issues, nil
}

func (r *reporter) getRepoTargetLink(data *ocsffindinginfo.DataSource) (string, error) {
	var repoURL = data.GetSourceCodeMetadata().GetRepositoryUrl()
	if !strings.HasPrefix(repoURL, "https://github.com") {
		return repoURL, nil
	}

	// A sample GH link looks like:
	// https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L1-L1
	var startLine, endLine uint32 = 1, 1
	if data.GetFileFindingLocationData().GetStartLine() > 0 {
		startLine = data.GetFileFindingLocationData().GetStartLine()
	}
	// Defensive approach which leads to fallback to the same start line in case end line is malformed.
	if el := data.GetFileFindingLocationData().GetEndLine(); el > 0 && el > startLine {
		endLine = data.GetFileFindingLocationData().GetEndLine()
	} else {
		endLine = startLine
	}

	res, err := url.JoinPath(
		repoURL,
		"blob",
		data.GetSourceCodeMetadata().GetReference(),
		data.GetUri().GetPath(),
	)
	if err != nil {
		return "", errors.Errorf("invalid repository target link: %w", err)
	}

	return res + fmt.Sprintf("#L%d-L%d", startLine, endLine), nil
}

func (r *reporter) getPriority(severity string) int {
	switch severity {
	case ocsf.VulnerabilityFinding_SEVERITY_ID_LOW.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER.String():
		return 4
	case ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String():
		return 3
	case ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String():
		return 2
	case ocsf.VulnerabilityFinding_SEVERITY_ID_FATAL.String(),
		ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String():
		return 1
	}
	return 0
}

func (r *reporter) getConfidence(confidence ocsf.VulnerabilityFinding_ConfidenceId) string {
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
