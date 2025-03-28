package types

// Check is a deps.dev ScoreCardV2 check
type Check struct {
	Name   string `json:"name,omitempty"`
	Score  int    `json:"score,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ScorecardV2 is a deps.dev ScoreCardV2 result
type ScorecardV2 struct {
	Date  string  `json:"date,omitempty"`
	Check []Check `json:"check,omitempty"`
	Score float64 `json:"score,omitempty"`
}

// Project is a deps.dev project
type Project struct {
	Type        string      `json:"type,omitempty"`
	Name        string      `json:"name,omitempty"`
	ObservedAt  int         `json:"observedAt,omitempty"`
	Issues      int         `json:"issues,omitempty"`
	Forks       int         `json:"forks,omitempty"`
	Stars       int         `json:"stars,omitempty"`
	Description string      `json:"description,omitempty"`
	License     string      `json:"license,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Link        string      `json:"link,omitempty"`
	ScorecardV2 ScorecardV2 `json:"scorecardV2,omitempty"`
}

// Version is a deps.dev version, main object in the response
type Version struct {
	Version                string    `json:"version,omitempty"`
	RefreshedAt            int       `json:"refreshedAt,omitempty"`
	IsDefault              bool      `json:"isDefault,omitempty"`
	Licenses               []string  `json:"licenses,omitempty"`
	DependentCount         int       `json:"dependentCount,omitempty"`
	DependentCountDirect   int       `json:"dependentCountDirect,omitempty"`
	DependentCountIndirect int       `json:"dependentCountIndirect,omitempty"`
	Projects               []Project `json:"projects,omitempty"`
}

// Response is a deps.dev response
type Response struct {
	Version        Version `json:"version,omitempty"`
	DefaultVersion string  `json:"defaultVersion,omitempty"`
}
