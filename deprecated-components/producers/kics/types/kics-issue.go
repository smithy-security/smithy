package types

// KICSOut represents the output of a KICS run.
type KICSOut struct {
	Queries []KICSQuery `json:"queries"`
}

// KICSQuery represents a KICS finding.
type KICSQuery struct {
	QueryName     string     `json:"query_name"`
	QueryID       string     `json:"query_id"`
	QueryURL      string     `json:"query_url"`
	Severity      string     `json:"severity"`
	Platform      string     `json:"platform"`
	CloudProvider string     `json:"cloud_provider"`
	Category      string     `json:"category"`
	Description   string     `json:"description"`
	DescriptionID string     `json:"description_id"`
	Files         []KICSFile `json:"files"`
}

// KICSFile represents the file section of a kics output.
type KICSFile struct {
	FileName      string `json:"file_name"`
	SimilarityID  string `json:"similarity_id"`
	Line          int    `json:"line"`
	ResourceType  string `json:"resource_type"`
	ResourceName  string `json:"resource_name"`
	IssueType     string `json:"issue_type"`
	SearchKey     string `json:"search_key"`
	SearchLine    int    `json:"search_line"`
	SearchValue   string `json:"search_value"`
	ExpectedValue string `json:"expected_value"`
	ActualValue   string `json:"actual_value"`
}
