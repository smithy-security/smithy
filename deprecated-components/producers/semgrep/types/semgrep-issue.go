package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Position represents where in the file the finding is located.
type Position struct {
	Col  int `json:"col"`
	Line int `json:"line"`
}

// Extra contains extra info needed for semgrep issue.
type Extra struct {
	Message  string   `json:"message"`
	Metavars Metavars `json:"metavars"`
	Metadata Metadata `json:"metadata"`
	Severity string   `json:"severity"`
	Lines    string   `json:"lines"`
}

// SemgrepIssue represents a semgrep issue.
type SemgrepIssue struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Position `json:"start"`
	End     Position `json:"end"`
	Extra   Extra    `json:"extra"`
}

// SemgrepResults represents a series of semgrep issues.
type SemgrepResults struct {
	Results []SemgrepIssue `'json:"results"`
}

// Metavars currently is empty but could represent more metavariables for semgrep.
type Metavars struct{}

// FlexibleIntField is a field that can be either a single int or a list of ints.
type FlexibleIntField []int32

// Metadata contains semgrep issue metadata
type Metadata struct {
	CWE FlexibleIntField `json:"cwe"`
}

func (f *FlexibleIntField) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		num, err := extractCWENumber(single)
		if err != nil {
			return err
		}
		*f = FlexibleIntField{num}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		nums := make([]int32, len(multiple))
		for i, s := range multiple {
			num, err := extractCWENumber(s)
			if err != nil {
				return fmt.Errorf("invalid CWE format at index %d: %s", i, s)
			}
			nums[i] = num
		}
		*f = FlexibleIntField(nums)
		return nil
	}

	return fmt.Errorf("invalid format for CWE field")
}

// ErrCWEInvalidFormat is returned when the CWE field is not in the expected format.
var ErrCWEInvalidFormat = fmt.Errorf("invalid CWE format")

// ErrCWEMissingPrefix is returned when the CWE field is missing the `CWE-` prefix.
var ErrCWEMissingPrefix = fmt.Errorf("missing `CWE-` prefix %w", ErrCWEInvalidFormat)

// ErrCWEInvalidNumber is returned when the CWE number is not a valid number.
var ErrCWEInvalidNumber = fmt.Errorf("invalid CWE number %w", ErrCWEInvalidFormat)

func extractCWENumber(s string) (int32, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) < 1 {
		return 0, fmt.Errorf("%w: %s", ErrCWEInvalidFormat, s)
	}

	cweID := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(cweID, "CWE-") {
		return 0, fmt.Errorf("%w: %s", ErrCWEMissingPrefix, cweID)
	}

	numStr := strings.TrimPrefix(cweID, "CWE-")
	num64, err := strconv.ParseInt(numStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %s, %w", ErrCWEInvalidNumber, numStr, err)
	}

	return int32(num64), nil
}
