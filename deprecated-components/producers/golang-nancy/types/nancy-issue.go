package types

// NancyOut represents the output of a nancy run that we care about.
type NancyOut struct {
	Vulnerable    []NancyAdvisories `json:"vulnerable"`
	Audited       []interface{}
	Exclusions    []interface{}
	Invalid       []interface{}
	NumAudited    int
	NumVulnerable int
	Version       string
}

// NancyAdvisories represents a nancy advisory section that we care about.
type NancyAdvisories struct {
	Coordinates     string                  `json:"Coordinates"`
	Reference       string                  `json:"Reference"`
	Vulnerabilities []*NancyVulnerabilities `json:"Vulnerabilities"`
}

// NancyVulnerabilities represents a nancy vulnerability.
type NancyVulnerabilities struct {
	ID          string `json:"Id"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	CvssScore   string `json:"CvssScore"`
	CvssVector  string `json:"CvssVector"`
	Cve         string `json:"Cve"`
	Cwe         string `json:"Cwe"`
	Reference   string `json:"Reference"`
}
