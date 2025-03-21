package main

import (
	"encoding/json"
	"testing"

	v1 "github.com/ocurity/dracon/api/proto/v1"

	"github.com/stretchr/testify/require"
)

func TestParseIssues(t *testing.T) {
	var results ModelScanOut
	err := json.Unmarshal([]byte(modelScanOut), &results)
	require.NoError(t, err)

	issues, err := parseIssues(&results)
	require.NoError(t, err)
	expectedIssue := []*v1.Issue{

		{
			Target:      "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
			Type:        "modelscan.scanners.PickleUnsafeOpScan",
			Title:       "Use of unsafe operator 'system' from module 'posix'",
			Description: "Use of unsafe operator 'system' from module 'posix'",
		},
		{
			Target:      "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
			Type:        "modelscan.scanners.PickleUnsafeOpScan",
			Title:       "Use of unsafe operator 'system' from module 'posix'",
			Description: "Use of unsafe operator 'system' from module 'posix'",
		},
		{
			Target:      "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
			Type:        "modelscan.scanners.PickleUnsafeOpScan",
			Title:       "Use of unsafe operator 'system' from module 'posix'",
			Description: "Use of unsafe operator 'system' from module 'posix'",
		},
		{
			Target:      "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
			Type:        "modelscan.scanners.PickleUnsafeOpScan",
			Title:       "Use of unsafe operator 'system' from module 'posix'",
			Description: "Use of unsafe operator 'system' from module 'posix'",
		},
	}

	require.Equal(t, expectedIssue, issues)
}

const modelScanOut = `{
  "modelscan_version": "0.5.0",
  "timestamp": "2024-01-25T17:56:00.855056",
  "input_path": "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
  "total_issues": 4,
  "summary": {
    "total_issues_by_severity": {
      "LOW": 1,
      "MEDIUM": 1,
      "HIGH": 1,
      "CRITICAL": 1
    }
  },
  "issues_by_severity": {
    "CRITICAL": [
      {
        "description": "Use of unsafe operator 'system' from module 'posix'",
        "operator": "system",
        "module": "posix",
        "source": "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
        "scanner": "modelscan.scanners.PickleUnsafeOpScan"
      }
    ],
    "MEDIUM": [
      {
        "description": "Use of unsafe operator 'system' from module 'posix'",
        "operator": "system",
        "module": "posix",
        "source": "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
        "scanner": "modelscan.scanners.PickleUnsafeOpScan"
      }
    ],
    "HIGH": [
      {
        "description": "Use of unsafe operator 'system' from module 'posix'",
        "operator": "system",
        "module": "posix",
        "source": "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
        "scanner": "modelscan.scanners.PickleUnsafeOpScan"
      }
    ],
    "LOW": [
      {
        "description": "Use of unsafe operator 'system' from module 'posix'",
        "operator": "system",
        "module": "posix",
        "source": "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl",
        "scanner": "modelscan.scanners.PickleUnsafeOpScan"
      }
    ]
  },
  "errors": [],
  "scanned": {
    "total_scanned": 4,
    "scanned_files": [
      "/Users/mehrinkiani/Documents/modelscan/notebooks/XGBoostModels/unsafe_model.pkl"
    ]
  }
}
`
