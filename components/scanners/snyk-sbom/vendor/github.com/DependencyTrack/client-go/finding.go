package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
)

type Finding struct {
	Attribution   FindingAttribution   `json:"attribution"`
	Analysis      FindingAnalysis      `json:"analysis"`
	Component     FindingComponent     `json:"component"`
	Matrix        string               `json:"matrix"`
	Vulnerability FindingVulnerability `json:"vulnerability"`
}

type FindingAnalysis struct {
	State      string `json:"state"`
	Suppressed bool   `json:"isSuppressed"`
}

type FindingAttribution struct {
	AlternateIdentifier string    `json:"alternateIdentifier"`
	AnalyzerIdentity    string    `json:"analyzerIdentity"`
	AttributedOn        int       `json:"attributedOn"`
	ReferenceURL        string    `json:"referenceUrl"`
	UUID                uuid.UUID `json:"uuid"`
}

type FindingComponent struct {
	UUID          uuid.UUID `json:"uuid"`
	Group         string    `json:"group"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	CPE           string    `json:"cpe"`
	PURL          string    `json:"purl"`
	LatestVersion string    `json:"latestVersion"`
	Project       uuid.UUID `json:"project"`
}

type FindingVulnerability struct {
	UUID                        uuid.UUID            `json:"uuid"`
	VulnID                      string               `json:"vulnId"`
	Source                      string               `json:"source"`
	Aliases                     []VulnerabilityAlias `json:"aliases"`
	Title                       string               `json:"title"`
	SubTitle                    string               `json:"subTitle"`
	Description                 string               `json:"description"`
	Recommendation              string               `json:"recommendation"`
	CVSSV2BaseScore             float64              `json:"cvssV2BaseScore"`
	CVSSV3BaseScore             float64              `json:"cvssV3BaseScore"`
	Severity                    string               `json:"severity"`
	SeverityRank                int                  `json:"severityRank"`
	OWASPRRBusinessImpactScore  float64              `json:"owaspBusinessImpactScore"`
	OWASPRRLikelihoodScore      float64              `json:"owaspLikelihoodScore"`
	OWASPRRTechnicalImpactScore float64              `json:"owaspTechnicalImpactScore"`
	EPSSScore                   float64              `json:"epssScore"`
	EPSSPercentile              float64              `json:"epssPercentile"`
	CWEs                        []CWE                `json:"cwes"`
}

type FindingService struct {
	client *Client
}

// GetAll fetches all findings for a given project.
func (f FindingService) GetAll(ctx context.Context, projectUUID uuid.UUID, suppressed bool, po PageOptions) (p Page[Finding], err error) {
	params := map[string]string{
		"suppressed": strconv.FormatBool(suppressed),
	}

	req, err := f.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/finding/project/%s", projectUUID), withParams(params), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := f.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

// ExportFPF exports the findings of a given project in the File Packaging Format (FPF).
func (f FindingService) ExportFPF(ctx context.Context, projectUUID uuid.UUID) (d []byte, err error) {
	req, err := f.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/finding/project/%s/export", projectUUID))
	if err != nil {
		return
	}

	var fpf string
	_, err = f.client.doRequest(req, &fpf)
	if err != nil {
		return
	}

	d = []byte(fpf)
	return
}

// AnalyzeProject triggers an analysis for a given project.
// This feature is available in Dependency-Track v4.7.0 and newer.
func (f FindingService) AnalyzeProject(ctx context.Context, projectUUID uuid.UUID) (token BOMUploadToken, err error) {
	req, err := f.client.newRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/finding/project/%s/analyze", projectUUID))
	if err != nil {
		return
	}

	var uploadRes bomUploadResponse
	_, err = f.client.doRequest(req, &uploadRes)
	if err != nil {
		return
	}

	token = uploadRes.Token
	return
}
