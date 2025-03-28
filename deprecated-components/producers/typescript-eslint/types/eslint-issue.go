package types

// Message represents where in the file the finding is located and the details of the finding.
type Message struct {
	RuleID   string `json:"ruleId"`
	Severity int    `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	EndLine  int    `json:"endLine"`
}

// ESLintIssue represents a ESLint Result.
type ESLintIssue struct {
	FilePath string    `json:"filePath"`
	Messages []Message `json:"messages"`
}
