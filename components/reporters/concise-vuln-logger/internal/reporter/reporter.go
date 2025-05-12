package reporter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

// NewVulnReporter returns a new json logger.
func NewVulnReporter() vulnReporter {
	return vulnReporter{}
}

type (
	vulnReporter struct{}
	vCode        struct {
		Path      string
		LineRange string
		Fix       string
		Cwe       string
	}
	vPkg struct {
		Purl        string
		FoundLoc    string
		Remediation string
		Cve         string
		Exploit     bool
	}
	vEnrichment struct {
		Provider       string
		Value          string
		EnrichmentName string
		Type           string
	}
	vDatasource struct {
		TargetType string
		Uri        string
		RepoURL    string
		Reference  string
		Purl       string
		Tag        string
	}
	vuln struct {
		Confidence  string
		Enrichments []*vEnrichment
		Title       string
		Datasources []*vDatasource
		Description string
		Severity    string
		Code        []vCode
		Pkg         []vPkg
		Vendor      string
	}
)

// Report logs the findings in json format.
func (j vulnReporter) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	for _, finding := range findings {
		if err := j.extractWhatWeCareAbout(ctx, finding); err != nil {
			return errors.Errorf("could not extract what we care about: %w", err)
		}
	}

	return nil
}

func (j vulnReporter) extractWhatWeCareAbout(ctx context.Context, finding *vf.VulnerabilityFinding) error {
	cV := vuln{}
	cV.Confidence = finding.Finding.GetConfidenceId().String()
	cV.Enrichments = make([]*vEnrichment, 0)
	for _, e := range finding.Finding.GetEnrichments() {
		cV.Enrichments = append(cV.Enrichments, &vEnrichment{
			Provider:       e.GetProvider(),
			Value:          e.GetValue(),
			EnrichmentName: e.GetName(),
			Type:           e.GetType(),
		})
	}
	cV.Title = finding.Finding.GetFindingInfo().GetTitle()
	ds := finding.Finding.GetFindingInfo().GetDataSources()
	for _, datasource := range ds {
		datas := ocsffindinginfo.DataSource{}
		if err := protojson.Unmarshal([]byte(datasource), &datas); err != nil {
			return errors.Errorf("could not json unmarshal finding: %w", err)
		}
		cV.Datasources = append(cV.Datasources, &vDatasource{
			TargetType: datas.GetTargetType().String(),
			Uri:        datas.GetUri().GetPath(),
			RepoURL:    datas.GetSourceCodeMetadata().GetRepositoryUrl(),
			Reference:  datas.GetSourceCodeMetadata().GetReference(),
			Purl:       datas.GetOciPackageMetadata().GetPackageUrl(),
			Tag:        datas.GetOciPackageMetadata().GetTag(),
		})
	}
	cV.Description = finding.Finding.GetMessage()
	cV.Severity = finding.Finding.GetSeverityId().String()
	cV.Code = make([]vCode, 0)
	cV.Pkg = make([]vPkg, 0)
	if finding.Finding.FindingInfo == nil || finding.Finding.FindingInfo.ProductUid == nil {
		return nil // errors.Errorf("unexpected nil: findingInfo.ProducUid for finding %#v", finding)
	}
	cV.Vendor = *finding.Finding.FindingInfo.ProductUid
	for _, v := range finding.Finding.Vulnerabilities {
		for _, ac := range v.AffectedCode {
			var c vCode
			if ac.File != nil {
				c.Path = *ac.File.Path
			}
			if ac != nil && ac.StartLine != nil && ac.EndLine != nil {
				c.LineRange = fmt.Sprintf("%d-%d", *ac.StartLine, *ac.EndLine)
			}
			if ac.Remediation != nil {
				c.Fix = ac.Remediation.GetDesc()
			}
			if v.Cwe != nil {
				c.Cwe = v.Cwe.GetUid()
			}
			cV.Code = append(cV.Code, c)
		}
		for _, ap := range v.AffectedPackages {
			var p vPkg
			if ap.Purl != nil {
				p.Purl = *ap.Purl
			}
			if ap.Path != nil {
				p.FoundLoc = *ap.Path
				p.Remediation = ap.Remediation.GetDesc()
			}
			if v.Cve != nil {
				p.Cve = v.Cve.GetUid()
			}
			if v.IsExploitAvailable != nil {
				p.Exploit = *v.IsExploitAvailable
			}
			cV.Pkg = append(cV.Pkg, p)
		}
	}

	b, err := json.Marshal(&cV)
	if err != nil {
		return errors.Errorf("could not json marshal cV: %w", err)
	}
	fmt.Println(string(b))
	if err := j.validate(cV); err != nil {
		return err
	}
	return nil
}

func (j vulnReporter) validate(cV vuln) error {
	if len(cV.Datasources) == 0 {
		return errors.Errorf("datasources is empty for finding %v", cV)
	}
	if cV.Description == "" {
		return errors.Errorf("description is empty for finding %v", cV)
	}
	if cV.Title == "" {
		return errors.Errorf("title is empty for finding %v", cV)
	}
	if cV.Vendor == "" {
		return errors.Errorf("vendor is empty for finding %v", cV)
	}
	if len(cV.Pkg) == 0 && len(cV.Code) == 0 {
		return errors.Errorf("pkg AND code is empty for finding %v", cV)
	}
	return nil
}
