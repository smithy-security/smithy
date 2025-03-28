package types

// TfSecOut represents the output of a tfsec run.
type TfSecOut struct {
	Results []TfSecResult
}

// TfSecResult represents a tfsec finding.
type TfSecResult struct {
	RuleID          string        `json:"rule_id"`
	LongID          string        `json:"long_id"`
	RuleDescription string        `json:"rule_description"`
	RuleProvider    string        `json:"rule_provider"`
	RuleService     string        `json:"rule_service"`
	Impact          string        `json:"impact"`
	Resolution      string        `json:"resolution"`
	Links           []string      `json:"links"`
	Description     string        `json:"description"`
	Severity        string        `json:"severity"`
	Warning         bool          `json:"warning"`
	Status          int32         `json:"status"`
	Resource        string        `json:"resource"`
	Location        TfSecLocation `json:"location"`
}

// TfSecLocation contains the location of a tfsec finding.
type TfSecLocation struct {
	Filename  string `json:"filename"`
	StartLine int32  `json:"start_line"`
	EndLine   int32  `json:"end_line"`
}
