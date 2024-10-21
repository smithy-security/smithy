package config

// Config contains all the data parsed from the conf.yaml file.
type Config struct {
	DefaultValues       DefaultValues              `json:"defaultValues"`
	Mappings            []Mappings                 `json:"mappings"`
	DescriptionTemplate string                     `json:"descriptionTemplate"`
	SyncMappings        []JiraToSmithyVulnMappings `json:"syncMappings"`
}

// CustomField represents a Jira Custom Field.
type CustomField struct {
	ID        string   `json:"id"`
	FieldType string   `json:"fieldType"`
	Values    []string `json:"values"`
}

// DefaultValues represents the Values that exist by default in all jira tickets we had access to.
type DefaultValues struct {
	Project         string        `json:"project"`
	Environment     string        `json:"environment"`
	IssueType       string        `json:"issueType"`
	Components      []string      `json:"components"`
	AffectsVersions []string      `json:"affectsVersions"`
	Labels          []string      `json:"labels,omitempty"`
	CustomFields    []CustomField `json:"customFields,omitempty"`
}

// Mappings holds a mapping between a smithy api field and it's corresponding jira field.
type Mappings struct {
	SmithyField string `json:"smithyField"`
	JiraField   string `json:"jiraField"`
	FieldType   string `json:"fieldType"`
}

// JiraToSmithyVulnMappings used by the sync utiity,
// this Mapping matches SmithyStatus-es to combinations of JiraStatus and JiraResolution, look in the sample config file for examples
// supported SmithyStatus values:
// * FalsePositive <-- will set the issue's FalsePositive flag to True
// * Duplicate <-- if the issue already exists in the database, will do nothing, otherwise will insert a new one
// * Resolved <-- will _REMOVE_ the finding from the database
// JiraStatus will be matched as a string
// JiraResolution will be matched as a string.
type JiraToSmithyVulnMappings struct {
	JiraStatus     string `json:"jiraStatus"`
	JiraResolution string `json:"jiraResolution"`
	SmithyStatus   string `json:"smithyStatus"`
}
