package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func TestSeverityFilter_Filter(t *testing.T) {
	tests := []struct {
		name             string
		envSeverity      string
		findings         []*vf.VulnerabilityFinding
		expectedFiltered int
		expectError      bool
	}{
		{
			name:        "Valid configuration with HIGH severity",
			envSeverity: "HIGH",
			findings: []*vf.VulnerabilityFinding{
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN,
					},
				},
			},
			expectedFiltered: 2,
			expectError:      false,
		},
		{
			name:        "Valid configuration with MEDIUM severity",
			envSeverity: "MEDIUM",
			findings: []*vf.VulnerabilityFinding{
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					},
				},
			},
			expectedFiltered: 2,
			expectError:      false,
		},
		{
			name:        "Invalid configuration with unknown severity",
			envSeverity: "INVALID",
			findings: []*vf.VulnerabilityFinding{
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
					},
				},
			},
			expectedFiltered: 0,
			expectError:      true,
		},
		{
			name:             "Empty findings list",
			envSeverity:      "HIGH",
			findings:         []*vf.VulnerabilityFinding{},
			expectedFiltered: 0,
			expectError:      false,
		},
		{
			name:        "Valid configuration with CRITICAL severity",
			envSeverity: "CRITICAL",
			findings: []*vf.VulnerabilityFinding{
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
					},
				},
				{
					Finding: &ocsf.VulnerabilityFinding{
						SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
					},
				},
			},
			expectedFiltered: 1,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("MINIMUM_SEVERITY", tt.envSeverity)
			defer os.Unsetenv("MINIMUM_SEVERITY")

			filter, err := NewSeverityFilter()
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			ctx := context.Background()
			filteredFindings, filtered, err := filter.Filter(ctx, tt.findings)
			require.NoError(t, err)
			filteredFindingsCount := 0
			for _, finding := range filteredFindings {
				for _, enrichment := range finding.Finding.Enrichments {
					if enrichment.Name == providerName {
						assert.Equal(t, providerName, *enrichment.Provider)
						assert.Equal(t, providerName, enrichment.Name)
						assert.NotEmpty(t, enrichment.Value)
						filteredFindingsCount++
					}
				}
			}
			assert.Equal(t, tt.expectedFiltered, filteredFindingsCount)
			assert.Equal(t, tt.expectedFiltered > 0, filtered)
		})
	}
}
