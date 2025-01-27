package enrichers

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/putil"
)

func createObjects() *smithyv1.EnrichedLaunchToolResponse {
	scanID := "7c78f6c9-b4b0-493c-a912-0bb0a4aaaaa0"
	times, _ := time.Parse(time.RFC3339, "2023-01-19T18:09:06.370037788Z")
	timestamp := timestamppb.New(times)
	si := smithyv1.ScanInfo{
		ScanUuid:      scanID,
		ScanStartTime: timestamp,
	}
	toolName := "SAT-Tool"
	response := smithyv1.LaunchToolResponse{
		ToolName: toolName,
		ScanInfo: &si,
	}
	enrichedResponse := smithyv1.EnrichedLaunchToolResponse{}

	var issues []*smithyv1.Issue
	var enrichedIssues []*smithyv1.EnrichedIssue
	for j := 0; j < 10; j++ {
		id := uuid.New()
		x := smithyv1.Issue{
			Target:     fmt.Sprintf("target-%d", j),
			Type:       fmt.Sprintf("type-%d", j),
			Title:      fmt.Sprintf("title-%d", j),
			Severity:   smithyv1.Severity_SEVERITY_INFO,
			Confidence: smithyv1.Confidence_CONFIDENCE_INFO,
			Uuid:       id.String(),
		}
		y := smithyv1.EnrichedIssue{
			RawIssue:      &x,
			FirstSeen:     response.ScanInfo.ScanStartTime,
			Count:         uint64(j),
			FalsePositive: false,
			UpdatedAt:     response.ScanInfo.ScanStartTime,
			Hash:          fmt.Sprintf("d41d8cd98f00b204e9800998ecf842%d", j),
		}
		issues = append(issues, &x)
		enrichedIssues = append(enrichedIssues, &y)
	}
	response.Issues = issues
	enrichedResponse.OriginalResults = &response
	enrichedResponse.Issues = enrichedIssues
	return &enrichedResponse
}

func TestLookupEnvOrString(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "Environment variable set",
			envKey:       "TEST_ENV_VAR",
			envValue:     "test value",
			defaultValue: "default value",
			expected:     "test value",
		},
		{
			name:         "Environment variable not set, default value returned",
			envKey:       "NON_EXISTENT_ENV_VAR",
			defaultValue: "default value",
			expected:     "default value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				os.Setenv(tc.envKey, tc.envValue)
				defer os.Unsetenv(tc.envKey)
			}

			result := LookupEnvOrString(tc.envKey, tc.defaultValue)

			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string // Environment variables to set
		args         []string          // Command-line arguments
		expectError  bool              // Whether an error is expected
		errorMessage string            // Error message, if any
	}{
		{
			name: "Valid flags via environment variables",
			envVars: map[string]string{
				"READ_PATH":  "/tmp/read",
				"WRITE_PATH": "/tmp/write",
			},
			args:        []string{},
			expectError: false,
		},
		{
			name:         "Missing read_path",
			envVars:      map[string]string{"WRITE_PATH": "/tmp/write"},
			args:         []string{},
			expectError:  true,
			errorMessage: "read_path is undefined",
		},
		{
			name:         "Missing write_path",
			envVars:      map[string]string{"READ_PATH": "/tmp/read"},
			args:         []string{},
			expectError:  true,
			errorMessage: "write_path is undefined",
		},
		{
			name:        "Valid flags via parameters",
			envVars:     map[string]string{},
			args:        []string{"-read_path", "/tmp/read", "-write_path", "/tmp/write"},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset flags
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			// Set environment variables and command-line arguments
			for key, value := range tc.envVars {
				os.Setenv(key, value)
			}
			os.Args = append([]string{"cmd"}, tc.args...)

			err := ParseFlags()

			// Check the result
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMessage)
			} else {
				assert.NoError(t, err)
			}

			for key := range tc.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestWriteData(t *testing.T) {
	enricherName := "tests-enricher"
	workdir, err := os.MkdirTemp("/tmp", "")
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(workdir, "raw"), 0755))

	tests := []struct {
		name             string
		enrichedResponse *smithyv1.EnrichedLaunchToolResponse
		expectError      bool
	}{
		{
			name:             "happy path",
			enrichedResponse: createObjects(),
			expectError:      false,
		},
		{
			name:             "nil enrichedResponse",
			enrichedResponse: nil,
			expectError:      true,
		},
		{
			name:             "nil originalResults",
			enrichedResponse: &smithyv1.EnrichedLaunchToolResponse{OriginalResults: nil},
			expectError:      true,
		},
		{
			name: "no enriched issues while originalResults present",
			enrichedResponse: &smithyv1.EnrichedLaunchToolResponse{
				OriginalResults: &smithyv1.LaunchToolResponse{
					Issues: []*smithyv1.Issue{
						{
							Target: "target",
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetWritePathForTests(workdir)

			err := WriteData(tc.enrichedResponse, enricherName)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				er, err := putil.LoadEnrichedNonAggregatedToolResponse(workdir)
				require.NoError(t, err)
				opt := cmp.Comparer(func(x, y *timestamppb.Timestamp) bool {
					return x.Nanos == y.Nanos
				})

				require.True(t, cmp.Equal([]*smithyv1.EnrichedLaunchToolResponse{tc.enrichedResponse}, er, protocmp.Transform(), opt),
					cmp.Diff([]*smithyv1.EnrichedLaunchToolResponse{tc.enrichedResponse}, er, protocmp.Transform()))

				r, err := putil.LoadToolResponse(filepath.Join(workdir, fmt.Sprintf("%s.raw.pb", tc.enrichedResponse.GetOriginalResults().GetToolName())))
				require.NoError(t, err)

				require.True(t, cmp.Equal([]*smithyv1.LaunchToolResponse{tc.enrichedResponse.OriginalResults}, r, protocmp.Transform(), opt),
					cmp.Diff([]*smithyv1.LaunchToolResponse{tc.enrichedResponse.OriginalResults}, r, protocmp.Transform()))
			}
		})
	}
}
