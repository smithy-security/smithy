package types

// pkg represents a package in the dependency check report.
type pkg struct {
	ID         string `json:"id"`
	Confidence string `json:"confidence"`
	URL        string `json:"url"`
}

// cvssv3 represents the CVSS v3 score of a vulnerability.
type cvssv3 struct {
	BaseScore             float64 `json:"baseScore"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
}

// cvssv2 represents the CVSS v2 score of a vulnerability.
type cvssv2 struct {
	Score float64 `json:"score"`
}

// Vulnerability represents a vulnerability in the dependency check report.
type Vulnerability struct {
	Source      string   `json:"source"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Cvssv3      cvssv3   `json:"cvssv3"`
	Cvssv2      cvssv2   `json:"cvssv2"`
	Cwes        []string `json:"cwes"`
	Description string   `json:"description"`
	Notes       string   `json:"notes"`
}

// dependency represents a dependency in the dependency check report.
type dependency struct {
	FileName        string          `json:"fileName"`
	FilePath        string          `json:"filePath"`
	Packages        []pkg           `json:"packages"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// DependencyCheckReport represents the dependency check report.
type DependencyCheckReport struct {
	Dependencies []dependency `json:"dependencies"`
}
