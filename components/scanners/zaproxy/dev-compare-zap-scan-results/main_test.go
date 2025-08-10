package main

import (
	"os"
	"sort"
	"testing"

	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestGetFindingIDs(t *testing.T) {
	tests := []struct {
		name     string
		sarifDoc *sarifschemav210.SchemaJson
		expected map[string]sets.Set[string]
	}{
		{
			name:     "nil sarif document",
			sarifDoc: nil,
			expected: map[string]sets.Set[string]{},
		},
		{
			name:     "empty sarif document",
			sarifDoc: &sarifschemav210.SchemaJson{},
			expected: map[string]sets.Set[string]{},
		},
		{
			name: "sarif document with no runs",
			sarifDoc: &sarifschemav210.SchemaJson{
				Runs: []sarifschemav210.Run{},
			},
			expected: map[string]sets.Set[string]{},
		},
		{
			name: "sarif document with empty runs",
			sarifDoc: &sarifschemav210.SchemaJson{
				Runs: []sarifschemav210.Run{
					{Results: []sarifschemav210.Result{}},
				},
			},
			expected: map[string]sets.Set[string]{},
		},
		{
			name: "sarif document with results but no rule IDs",
			sarifDoc: &sarifschemav210.SchemaJson{
				Runs: []sarifschemav210.Run{
					{
						Results: []sarifschemav210.Result{
							{
								RuleId: nil,
								Locations: []sarifschemav210.Location{
									{
										PhysicalLocation: &sarifschemav210.PhysicalLocation{
											ArtifactLocation: &sarifschemav210.ArtifactLocation{
												Uri: stringPtr("file1.go"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string]sets.Set[string]{},
		},
		{
			name: "sarif document with results but no locations",
			sarifDoc: &sarifschemav210.SchemaJson{
				Runs: []sarifschemav210.Run{
					{
						Results: []sarifschemav210.Result{
							{
								RuleId:    stringPtr("rule1"),
								Locations: []sarifschemav210.Location{},
							},
						},
					},
				},
			},
			expected: map[string]sets.Set[string]{},
		},
		{
			name: "sarif document with valid findings",
			sarifDoc: &sarifschemav210.SchemaJson{
				Runs: []sarifschemav210.Run{
					{
						Results: []sarifschemav210.Result{
							{
								RuleId: stringPtr("rule1"),
								Locations: []sarifschemav210.Location{
									{
										PhysicalLocation: &sarifschemav210.PhysicalLocation{
											ArtifactLocation: &sarifschemav210.ArtifactLocation{
												Uri: stringPtr("file1.go"),
											},
										},
									},
								},
							},
							{
								RuleId: stringPtr("rule2"),
								Locations: []sarifschemav210.Location{
									{
										PhysicalLocation: &sarifschemav210.PhysicalLocation{
											ArtifactLocation: &sarifschemav210.ArtifactLocation{
												Uri: stringPtr("file2.go"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string]sets.Set[string]{
				"rule1": sets.New("file1.go"),
				"rule2": sets.New("file2.go"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFindingIDs(tt.sarifDoc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name          string
		sarif1        *sarifschemav210.SchemaJson
		sarif2        *sarifschemav210.SchemaJson
		expectedRules map[string][]string
		expectedPaths map[string]map[string][]string
	}{
		{
			name:   "both sarif files are nil",
			sarif1: nil,
			sarif2: nil,
			expectedRules: map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {},
			},
		},
		{
			name:   "sarif1 is nil, sarif2 has content",
			sarif1: nil,
			sarif2: createTestSarif([]string{"rule1"}, []string{"file1.go"}),
			expectedRules: map[string][]string{
				"first-only":  {},
				"second-only": {"rule1"},
				"both":        {},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {},
				"second-only": {"rule1": {"file1.go"}},
				"both":        {},
			},
		},
		{
			name:   "sarif1 has content, sarif2 is nil",
			sarif1: createTestSarif([]string{"rule1"}, []string{"file1.go"}),
			sarif2: nil,
			expectedRules: map[string][]string{
				"first-only":  {"rule1"},
				"second-only": {},
				"both":        {},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {"rule1": {"file1.go"}},
				"second-only": {},
				"both":        {},
			},
		},
		{
			name:   "both sarif files are empty",
			sarif1: &sarifschemav210.SchemaJson{},
			sarif2: &sarifschemav210.SchemaJson{},
			expectedRules: map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {},
			},
		},
		{
			name:   "sarif1 is smaller than sarif2",
			sarif1: createTestSarif([]string{"rule1"}, []string{"file1.go"}),
			sarif2: createTestSarif([]string{"rule1", "rule2", "rule3"}, []string{"file1.go", "file2.go", "file3.go"}),
			expectedRules: map[string][]string{
				"first-only":  {},
				"second-only": {"rule2", "rule3"},
				"both":        {"rule1"},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only": {},
				"second-only": {
					"rule1": {"file2.go", "file3.go"},
					"rule2": {"file1.go", "file2.go", "file3.go"},
					"rule3": {"file1.go", "file2.go", "file3.go"},
				},
				"both": {"rule1": {"file1.go"}},
			},
		},
		{
			name:   "sarif1 is larger than sarif2",
			sarif1: createTestSarif([]string{"rule1", "rule2", "rule3", "rule4"}, []string{"file1.go", "file2.go", "file3.go", "file4.go"}),
			sarif2: createTestSarif([]string{"rule1", "rule2"}, []string{"file1.go", "file2.go"}),
			expectedRules: map[string][]string{
				"first-only":  {"rule3", "rule4"},
				"second-only": {},
				"both":        {"rule1", "rule2"},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only": {
					"rule1": {"file3.go", "file4.go"},
					"rule2": {"file3.go", "file4.go"},
					"rule3": {"file1.go", "file2.go", "file3.go", "file4.go"},
					"rule4": {"file1.go", "file2.go", "file3.go", "file4.go"}},
				"second-only": {},
				"both":        {"rule1": {"file1.go", "file2.go"}, "rule2": {"file1.go", "file2.go"}},
			},
		},
		{
			name:   "sarif1 and sarif2 have no common rules",
			sarif1: createTestSarif([]string{"rule1", "rule2"}, []string{"file1.go", "file2.go"}),
			sarif2: createTestSarif([]string{"rule3", "rule4"}, []string{"file3.go", "file4.go"}),
			expectedRules: map[string][]string{
				"first-only":  {"rule1", "rule2"},
				"second-only": {"rule3", "rule4"},
				"both":        {},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {"rule1": {"file1.go", "file2.go"}, "rule2": {"file1.go", "file2.go"}},
				"second-only": {"rule3": {"file3.go", "file4.go"}, "rule4": {"file3.go", "file4.go"}},
				"both":        {},
			},
		},
		{
			name:   "sarif1 and sarif2 have identical content",
			sarif1: createTestSarif([]string{"rule1", "rule2"}, []string{"file1.go", "file2.go"}),
			sarif2: createTestSarif([]string{"rule1", "rule2"}, []string{"file1.go", "file2.go"}),
			expectedRules: map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {"rule1", "rule2"},
			},
			expectedPaths: map[string]map[string][]string{
				"first-only":  {},
				"second-only": {},
				"both":        {"rule1": {"file1.go", "file2.go"}, "rule2": {"file1.go", "file2.go"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, paths := compare(tt.sarif1, tt.sarif2)

			// Sort slices for consistent comparison
			for _, v := range rules {
				sort.Strings(v)
			}
			for _, v := range tt.expectedRules {
				sort.Strings(v)
			}

			assert.Equal(t, tt.expectedRules, rules)
			// Compare maps key by key
			assert.Equal(t, len(tt.expectedPaths), len(paths))
			for key, expectedMap := range tt.expectedPaths {
				assert.Equal(t, len(tt.expectedPaths[key]), len(paths[key]))
				for nestedKey, expectedSlice := range expectedMap {
					actualSlice, exists := paths[key][nestedKey]
					assert.True(t, exists, "Key %s should exist", nestedKey)
					assert.ElementsMatch(t, expectedSlice, actualSlice)
				}
			}
		})
	}
}

func TestReadSarif(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty file",
			content:     "",
			expectError: true,
			errorMsg:    "failed to decode SARIF file",
		},
		{
			name:        "malformed JSON - missing closing brace",
			content:     `{"$schema": "test"`,
			expectError: true,
			errorMsg:    "failed to decode SARIF file",
		},
		{
			name:        "valid SARIF structure",
			content:     `{"$schema": "test","version": "2.1.0", "runs": [{"tool":{"driver":{"name":"tests"}},"results": []}]}`,
			expectError: false,
		},
		{
			name:        "file with only whitespace",
			content:     "   \n\t  ",
			expectError: true,
			errorMsg:    "failed to decode SARIF file",
		},
		{
			name:        "file with null bytes",
			content:     "\x00\x00\x00",
			expectError: true,
			errorMsg:    "failed to decode SARIF file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test_sarif_*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			// Write content to file
			_, err = tmpFile.WriteString(tt.content)
			require.NoError(t, err)
			tmpFile.Close()

			// Test readSarif function
			result, err := readSarif(tmpFile.Name())

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestReadSarifFileNotFound(t *testing.T) {
	_, err := readSarif("nonexistent_file.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

// Helper function to create test SARIF documents
func createTestSarif(ruleIDs []string, filePaths []string) *sarifschemav210.SchemaJson {
	if len(ruleIDs) == 0 {
		return &sarifschemav210.SchemaJson{}
	}

	results := make([]sarifschemav210.Result, len(ruleIDs))
	for i, ruleID := range ruleIDs {
		locations := make([]sarifschemav210.Location, len(filePaths))
		for j, filePath := range filePaths {
			locations[j] = sarifschemav210.Location{
				PhysicalLocation: &sarifschemav210.PhysicalLocation{
					ArtifactLocation: &sarifschemav210.ArtifactLocation{
						Uri: stringPtr(filePath),
					},
				},
			}
		}
		results[i] = sarifschemav210.Result{
			RuleId:    stringPtr(ruleID),
			Locations: locations,
		}
	}

	return &sarifschemav210.SchemaJson{
		Runs: []sarifschemav210.Run{
			{Results: results},
		},
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
