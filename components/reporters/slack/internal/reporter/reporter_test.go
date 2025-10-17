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

	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter"
	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter/slack"
)

var (
	//go:embed testdata/expected_thread_msg.txt
	expectedThreadMsg string
	//go:embed testdata/expected_msg1.txt
	expectedMsg1 string
	//go:embed testdata/expected_msg2.txt
	expectedMsg2 string
	//go:embed testdata/expected_msg3.txt
	expectedMsg3 string
)

func TestReporter_Report(t *testing.T) {
	const (
		testSmithyDashURL = "https://smithy.example.com"
		testInstanceID    = "instance-1234"
		testInstanceName  = "Test Instance"
		testThreadID      = "thread-5678"
	)

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer parentCancel()

	var (
		ctrl              = gomock.NewController(t)
		mockMessageSender = NewMockMessageSender(ctrl)
		createThreadErr   = errors.New("create thread error")
		sendMessagesErr   = errors.New("send messages error")
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
				Title:      utils.Ptr("Vulnerability 1"),
				Desc:       utils.Ptr("Description 1"),
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				VendorName: utils.Ptr("gosec"),
				Cve: &ocsf.Cve{
					Uid:  "CVE-2022-1234",
					Desc: utils.Ptr("CVE Description"),
				},
				Cwe: &ocsf.Cwe{
					Caption: utils.Ptr("CWE-79"),
					SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
				},
			},
			{
				Title:      utils.Ptr("Vulnerability 2"),
				Desc:       utils.Ptr("Description 2"),
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				VendorName: utils.Ptr("semgrep"),
				Cwe: &ocsf.Cwe{
					Caption: utils.Ptr("CWE-89"),
					SrcUrl:  utils.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
				},
			},
			{
				Title:      utils.Ptr("Vulnerability 3"),
				Desc:       utils.Ptr("Description 3"),
				Severity:   utils.Ptr("SEVERITY_ID_CRITICAL"),
				VendorName: utils.Ptr("snyk"),
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
					ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      utils.Ptr("High"),
					Vulnerabilities: vulnerabilities,
				},
			},
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
					ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
					Confidence:      utils.Ptr("High"),
					Vulnerabilities: []*ocsf.Vulnerability{vulnerabilities[0]},
				},
			},
		}
	)

	smithyDashURL, err := url.Parse(testSmithyDashURL)
	require.NoError(t, err)

	reporterConfig := reporter.Conf{
		SmithyInstanceID:   testInstanceID,
		SmithyInstanceName: testInstanceName,
		SmithyDashURL:      smithyDashURL,
		SlackClientConfig: slack.Config{
			Token:      "ASDF",
			ChannelID:  "asdf",
			Debug:      false,
			BaseClient: nil,
		},
	}
	testReporter, err := reporter.NewSlackReporter(
		&reporterConfig,
		mockMessageSender,
	)
	require.NoError(t, err)

	t.Run("successful report", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()
		expectedMsgs := []string{
			expectedMsg1,
			expectedMsg2,
			expectedMsg3,
		}
		gomock.InOrder(
			mockMessageSender.EXPECT().CreateThread(ctx, expectedThreadMsg).Return(testThreadID, nil),
			mockMessageSender.EXPECT().SendMessages(ctx, testThreadID, expectedMsgs).Return(nil),
		)

		err = testReporter.Report(ctx, findings)
		require.NoError(t, err)
	})

	t.Run("empty findings list", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		err = testReporter.Report(ctx, []*vf.VulnerabilityFinding{})
		require.NoError(t, err)
	})

	t.Run("error creating thread", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()
		expectedThreadMsg := "3 findings found by *Test Instance*. Details in the thread.\n"
		mockMessageSender.EXPECT().
			CreateThread(ctx, expectedThreadMsg).
			Return("", createThreadErr)

		err = testReporter.Report(ctx, findings)
		assert.Error(t, err)
		assert.ErrorIs(t, err, createThreadErr)
	})

	t.Run("error sending messages", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		expectedThreadMsg := "3 findings found by *Test Instance*. Details in the thread.\n"
		expectedMsgs := []string{
			"Smithy detected a vulnerability in *[github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76](https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76)*.\n\n*Vulnerability 1:*\nDescription 1.\n\n\n*Location:* *util/middleware/middleware.go* between line 70 and 76 on branch *master*.\n\n\n*Finding info:*\n- *ID:* [1](https://smithy.example.com/issues/1)\n- *Confidence:* High\n- *CWE:* [CWE-79](https://cwe.mitre.org/data/definitions/79.html)\n- *CVE:* CVE-2022-1234\n- *Reporting Tool:* gosec\n- *Detected by Run:* [Test Instance](https://smithy.example.com/runs/instance-1234)\n",
			"Smithy detected a vulnerability in *[github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76](https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76)*.\n\n*Vulnerability 2:*\nDescription 2.\n\n\n*Location:* *util/middleware/middleware.go* between line 70 and 76 on branch *master*.\n\n\n*Finding info:*\n- *ID:* [1](https://smithy.example.com/issues/1)\n- *Confidence:* High\n- *CWE:* [CWE-89](https://cwe.mitre.org/data/definitions/89.html)\n- *CVE:* -\n- *Reporting Tool:* semgrep\n- *Detected by Run:* [Test Instance](https://smithy.example.com/runs/instance-1234)\n",
			"Smithy detected a vulnerability in *[github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76](https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76)*.\n\n*Vulnerability 3:*\nDescription 3.\n\n\n*Location:* *util/middleware/middleware.go* between line 70 and 76 on branch *master*.\n\n\n*Finding info:*\n- *ID:* [1](https://smithy.example.com/issues/1)\n- *Confidence:* High\n- *CWE:* [-](-)\n- *CVE:* CVE-2023-5678\n- *Reporting Tool:* snyk\n- *Detected by Run:* [Test Instance](https://smithy.example.com/runs/instance-1234)\n",
		}
		gomock.InOrder(
			mockMessageSender.EXPECT().CreateThread(ctx, expectedThreadMsg).Return(testThreadID, nil),
			mockMessageSender.EXPECT().SendMessages(ctx, testThreadID, expectedMsgs).Return(sendMessagesErr),
		)

		err = testReporter.Report(ctx, findings)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sendMessagesErr)
	})

	t.Run("simpler findings", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		simpleThreadMsg := "1 findings found by *Test Instance*. Details in the thread.\n"
		simpleMsgs := []string{
			"Smithy detected a vulnerability in *[github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76](https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L70-L76)*.\n\n*Vulnerability 1:*\nDescription 1.\n\n\n*Location:* *util/middleware/middleware.go* between line 70 and 76 on branch *master*.\n\n\n*Finding info:*\n- *ID:* [1](https://smithy.example.com/issues/1)\n- *Confidence:* High\n- *CWE:* [CWE-79](https://cwe.mitre.org/data/definitions/79.html)\n- *CVE:* CVE-2022-1234\n- *Reporting Tool:* gosec\n- *Detected by Run:* [Test Instance](https://smithy.example.com/runs/instance-1234)\n",
		}
		gomock.InOrder(
			mockMessageSender.EXPECT().CreateThread(ctx, simpleThreadMsg).Return(testThreadID, nil),
			mockMessageSender.EXPECT().SendMessages(ctx, testThreadID, simpleMsgs).Return(nil),
		)

		err = testReporter.Report(ctx, simpleFindings1)
		require.NoError(t, err)
	})
}
