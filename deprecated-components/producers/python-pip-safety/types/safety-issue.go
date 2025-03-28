package types

// Vulnerability describes a pip safety vulnerability entry.
type Vulnerability struct {
	// Vulnerability_id                               string
	PackageName                                string   `json:"package_name"`
	VulnerableSpec                             []string `json:"vulnerable_spec"`
	AllVulnerableSpecs                         []string `json:"all_vulnerable_specs"`
	AnalyzedVersion                            string   `json:"analyzed_version"`
	Advisory                                   string   `json:"advisory"`
	PublishedDate                              string   `json:"published_date"`
	FixedVersions                              []string `json:"fixed_versions"`
	ClosestVersionsWithoutKnownVulnerabilities []string `json:"closest_version_without_known_vulnerabilities"`
	Resources                                  []string `json:"resources"`
	CVE                                        string   `json:"cve"`
	Severity                                   string   `json:"severity"`
	AffectedVersions                           []string `json:"affected_versions"`
	MoreInfoURL                                string   `json:"more_info_url"`
}

// Out represents the json output of a pip safety run.
type Out struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
