package reporter_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/encoding/protojson"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer"
	"github.com/smithy-security/smithy/components/reporters/jira/internal/reporter"
)

func ptr[T any](v T) *T {
	return &v
}

func TestReporter_Report(t *testing.T) {
	const (
		testBaseURL = "https://smithy.example.com"
		testRunID   = "run-1234"
		testRunName = "Test Run"
	)

	expectedDesc1, err := os.ReadFile(filepath.Join("testdata", "expected_issue1.txt"))
	require.NoError(t, err)
	expectedDesc2, err := os.ReadFile(filepath.Join("testdata", "expected_issue2.txt"))
	require.NoError(t, err)
	expectedDesc3, err := os.ReadFile(filepath.Join("testdata", "expected_issue3.txt"))
	require.NoError(t, err)

	var (
		ctrl             = gomock.NewController(t)
		mockIssueCreator = NewMockIssueCreator(ctrl)
		baseURL, _       = url.Parse(testBaseURL)
		batchCreateErr   = errors.New("batch create error")
		dataSourceRepo   = &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "util/middleware/middleware.go",
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   70,
					EndLine:     76,
					StartColumn: 4,
					EndColumn:   4,
				},
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "https://github.com/0c34/govwa",
				Reference:     "master",
			},
		}
		dataSourceRepoJson, _ = protojson.Marshal(dataSourceRepo)
		vulnerabilities       = []*ocsf.Vulnerability{
			{
				Title:      ptr("Vulnerability 1"),
				Desc:       ptr("Description 1"),
				Severity:   ptr("SEVERITY_ID_MEDIUM"),
				VendorName: ptr("gosec"),
				Cve: &ocsf.Cve{
					Uid:  "CVE-2022-1234",
					Desc: ptr("CVE Description"),
				},
				Cwe: &ocsf.Cwe{
					Caption: ptr("CWE-79"),
					SrcUrl:  ptr("https://cwe.mitre.org/data/definitions/79.html"),
				},
			},
			{
				Title:      ptr("Vulnerability 2"),
				Desc:       ptr("Description 2"),
				Severity:   ptr("SEVERITY_ID_HIGH"),
				VendorName: ptr("semgrep"),
				Cwe: &ocsf.Cwe{
					Caption: ptr("CWE-89"),
					SrcUrl:  ptr("https://cwe.mitre.org/data/definitions/89.html"),
				},
			},
			{
				Title:      ptr("Vulnerability 3"),
				Desc:       ptr("Description 3"),
				Severity:   ptr("SEVERITY_ID_CRITICAL"),
				VendorName: ptr("snyk"),
				Cve: &ocsf.Cve{
					Uid: "CVE-2023-5678",
				},
			},
		}
		findings = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					FindingInfo: &ocsf.FindingInfo{
						DataSources: []string{
							string(dataSourceRepoJson),
						},
					},
					ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      ptr("High"),
					Vulnerabilities: vulnerabilities,
				},
			},
		}

		expectedIssue1 = issuer.Issue{
			Summary:     "Vulnerability 1",
			ID:          1,
			Priority:    "Medium",
			Description: string(expectedDesc1),
		}
		expectedIssue2 = issuer.Issue{
			Summary:     "Vulnerability 2",
			ID:          1,
			Priority:    "High",
			Description: string(expectedDesc2),
		}
		expectedIssue3 = issuer.Issue{
			Summary:     "Vulnerability 3",
			ID:          1,
			Priority:    "Highest",
			Description: string(expectedDesc3),
		}
		expectedIssues = []issuer.Issue{
			expectedIssue1,
			expectedIssue2,
			expectedIssue3,
		}

		simpleFindings1 = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					FindingInfo: &ocsf.FindingInfo{
						DataSources: []string{
							string(dataSourceRepoJson),
						},
					},
					ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      ptr("High"),
					Vulnerabilities: []*ocsf.Vulnerability{vulnerabilities[0]},
				},
			},
		}
		simpleFindings2 = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					FindingInfo: &ocsf.FindingInfo{
						DataSources: []string{
							string(dataSourceRepoJson),
						},
					},
					ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      ptr("High"),
					Vulnerabilities: []*ocsf.Vulnerability{vulnerabilities[1]},
				},
			},
		}
		simpleFindings3 = []*vf.VulnerabilityFinding{
			{
				ID: 1,
				Finding: &ocsf.VulnerabilityFinding{
					FindingInfo: &ocsf.FindingInfo{
						DataSources: []string{
							string(dataSourceRepoJson),
						},
					},
					ConfidenceId:    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      ptr("High"),
					Vulnerabilities: []*ocsf.Vulnerability{vulnerabilities[2]},
				},
			},
		}

		issueContext = reporter.IssueContext{
			SmithyInstanceBaseURL: baseURL,
			SmithyRunID:           testRunID,
			SmithyRunName:         testRunName,
		}
	)

	testReporter, err := reporter.New(issueContext, mockIssueCreator)
	require.NoError(t, err)

	t.Run("successful report", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreate(ctx, expectedIssues).
			Return(uint(3), true, nil)

		err = testReporter.Report(ctx, findings)
		require.NoError(t, err)
	})

	t.Run("empty findings list", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = testReporter.Report(ctx, []*vf.VulnerabilityFinding{})
		require.NoError(t, err)
	})

	t.Run("failed to create issues with false bool", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreate(ctx, []issuer.Issue{expectedIssue1}).
			Return(uint(0), false, batchCreateErr)

		err = testReporter.Report(ctx, simpleFindings1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, batchCreateErr)
	})

	t.Run("partial success with true bool", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreate(ctx, []issuer.Issue{expectedIssue2}).
			Return(uint(1), true, batchCreateErr)

		err = testReporter.Report(ctx, simpleFindings2)
		require.NoError(t, err)
	})

	t.Run("no issues created", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreate(ctx, []issuer.Issue{expectedIssue3}).
			Return(uint(0), false, nil)

		err = testReporter.Report(ctx, simpleFindings3)
		require.NoError(t, err)
	})
}
