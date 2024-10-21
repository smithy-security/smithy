package document

import (
	"time"
)

// Document represents a Smithy result (issue) object.
type Document struct {
	// The fields below are not used in this consumer. We use the text versions instead.
	Annotations    map[string]string `json:"annotations"`
	ConfidenceText string            `json:"confidence_text"`
	Count          string            `json:"count"`
	CVE            string            `json:"cve"`
	CVSS           string            `json:"cvss"`
	Description    string            `json:"description"`
	FalsePositive  string            `json:"false_positive"`
	FirstFound     time.Time         `json:"first_found"`
	Hash           string            `json:"hash"`
	ScanID         string            `json:"scan_id"`
	ScanStartTime  time.Time         `json:"scan_start_time"`
	SeverityText   string            `json:"severity_text"`
	Source         string            `json:"source"`
	Target         string            `json:"target"`
	Title          string            `json:"title"`
	ToolName       string            `json:"tool_name"`
	Type           string            `json:"type"` // The fields below are not used in this consumer. We use the text versions instead.
	// Severity   v1.Severity   `json:"severity"`
	// Confidence v1.Confidence `json:"confidence"`
}
