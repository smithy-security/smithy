package reporter_test

import (
	"context"
	_ "embed"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/smithy-security/pkg/utils"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/reporters/linear/internal/config"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/linear/client"
	"github.com/smithy-security/smithy/components/reporters/linear/internal/reporter"
)

var (
	//go:embed testdata/expected_issue1.txt
	expectedIssue1Description string
	//go:embed testdata/expected_issue2.txt
	expectedIssue2Description string
)

func TestReporter_Report(t *testing.T) {
	const (
		testSmithyDashURL = "https://smithy.example.com"
		testInstanceID    = "instance-1234"
		testInstanceName  = "Test Instance"
		testLinearAPIKey  = "lin_api_key_test"
		testLinearBaseURL = "https://api.linear.app"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl              = gomock.NewController(t)
		mockIssueCreator  = NewMockIssueCreator(ctrl)
		batchCreateErr    = errors.New("batch create error")
		partialSuccessErr = errors.New("partial success error")
		dataSourceRepo    = &ocsffindinginfo.DataSource{
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
				Title:      utils.Ptr("SQL Injection Vulnerability"),
				Desc:       utils.Ptr("SQL injection vulnerability found in user input handling"),
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				VendorName: utils.Ptr("semgrep"),
				Cve: &ocsf.Cve{
					Uid:  "CVE-2022-1234",
					Desc: utils.Ptr("SQL injection vulnerability in web application"),
				},
				Cwe: &ocsf.Cwe{
					Caption: utils.Ptr("CWE-89"),
					SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
				},
			},
			{
				Title:      utils.Ptr("Cross-site Scripting (XSS)"),
				Desc:       utils.Ptr("Reflected XSS vulnerability in search functionality"),
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				VendorName: utils.Ptr("gosec"),
				Cve: &ocsf.Cve{
					Uid:  "CVE-2023-5678",
					Desc: utils.Ptr("XSS vulnerability allowing script injection"),
				},
				Cwe: &ocsf.Cwe{
					Caption: utils.Ptr("CWE-79"),
					SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
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
					ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      utils.Ptr("High"),
					Vulnerabilities: vulnerabilities,
				},
			},
		}
		expectedIssueRequests = []linear.CreateIssueRequest{
			{
				Title:       "SQL Injection Vulnerability",
				Description: expectedIssue1Description,
				Priority:    2,
			},
			{
				Title:       "Cross-site Scripting (XSS)",
				Description: expectedIssue2Description,
				Priority:    3,
			},
		}
		successfulResponses = []linear.CreateIssueResponse{
			{
				ID:  "issue-001",
				URL: "https://linear.app/team/issue/issue-001",
			},
			{
				ID:  "issue-002",
				URL: "https://linear.app/team/issue/issue-002",
			},
		}
		partialResponses = []linear.CreateIssueResponse{
			{
				ID:  "issue-001",
				URL: "https://linear.app/team/issue/issue-001",
			},
		}
	)

	smithyDashURL, err := url.Parse(testSmithyDashURL)
	require.NoError(t, err)

	linearBaseURL, err := url.Parse(testLinearBaseURL)
	require.NoError(t, err)

	testReporter, err := reporter.New(
		config.Config{
			Linear: client.Config{
				APIKey:  testLinearAPIKey,
				BaseURL: linearBaseURL,
			},
			SmithyInstanceID:   testInstanceID,
			SmithyInstanceName: testInstanceName,
			SmithyDashURL:      smithyDashURL,
		},
		mockIssueCreator,
	)
	require.NoError(t, err)

	t.Run("it should successfully report", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreateIssues(ctx, expectedIssueRequests).
			Return(successfulResponses, nil)

		err = testReporter.Report(ctx, findings)
		require.NoError(t, err)
	})

	t.Run("it should return early when no findings are passed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		err = testReporter.Report(ctx, []*vf.VulnerabilityFinding{})
		require.NoError(t, err)
	})

	t.Run("it should fail when batch creation hard fails", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreateIssues(ctx, expectedIssueRequests).
			Return([]linear.CreateIssueResponse{}, batchCreateErr)

		err = testReporter.Report(ctx, findings)
		assert.Error(t, err)
		assert.ErrorIs(t, err, batchCreateErr)
		assert.Contains(t, err.Error(), "could not batch create issues")
	})

	t.Run("it should return an error when batch creation partially fails", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		mockIssueCreator.EXPECT().
			BatchCreateIssues(ctx, expectedIssueRequests).
			Return(partialResponses, partialSuccessErr)

		err = testReporter.Report(ctx, findings)
		assert.Error(t, err)
		assert.ErrorIs(t, err, partialSuccessErr)
		assert.Contains(t, err.Error(), "partially created issues")
	})

	t.Run("it should return an error when the issue creator is invalid", func(t *testing.T) {
		_, err := reporter.New(
			config.Config{
				Linear: client.Config{
					APIKey:  testLinearAPIKey,
					BaseURL: linearBaseURL,
				},
				SmithyInstanceID:   testInstanceID,
				SmithyInstanceName: testInstanceName,
				SmithyDashURL:      smithyDashURL,
			},
			nil,
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issue creator cannot be nil")
	})
}
