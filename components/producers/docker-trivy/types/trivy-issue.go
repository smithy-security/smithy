package types

// CombinedOut represents the output of multiple Trivy runs (useful when using the Trivy Smithy tool to scan multiple images); the key is the name of the image file that was scanned.
type CombinedOut map[string]TrivyOut

// TrivyOut represents the output of a trivy run that we care about.
type TrivyOut struct {
	Results []TrivyResults `json:"Results"`
}

// TrivyResults is a single result/finding.
type TrivyResults struct {
	Vulnerable []*TrivyVulnerability `json:"Vulnerabilities"`
	Target     string
	Type       string
}

// TrivyVulnerability represents a trivy vulnerability section with only the fields that we care about.
type TrivyVulnerability struct {
	CVE              string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	PrimaryURL       string             `json:"PrimaryURL"`
	Title            string             `json:"Title"`
	Description      string             `json:"Description"`
	Severity         string             `json:"Severity"`
	CweIDs           []string           `json:"CweIds"`
	CVSS             TrivyCVSS          `json:"CVSS"`
	PkgIdentifier    TrivyPkgIdentifier `json:"PkgIdentifier"`
}

// TrivyCVSS wraps Trivy CVSS info struct.
type TrivyCVSS struct {
	Nvd TrivyNvd `json:"nvd"`
}

// TrivyNvd wraps Trivy Nvd structure inside the CVSS struct.
type TrivyNvd struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

// TrivyPkgIdentifier represents the package identifier in the trivy output.
type TrivyPkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}
