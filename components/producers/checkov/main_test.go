package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
)

const (
	sarifInputPath     = "exampleData/results_sarif.sarif"
	cyclonedxInputPath = "exampleData/results_cyclonedx.json"
)

func TestRunSarif(t *testing.T) {
	workspace, err := os.MkdirTemp("", "smithy")
	require.NoError(t, err)

	defer require.NoError(t, os.RemoveAll(workspace))

	producers.OutFile = filepath.Join(workspace, "out.pb")
	input, err := os.ReadFile(sarifInputPath)
	require.NoError(t, err)
	require.NoError(t, run(input, ""))

	_, err = os.Stat(producers.OutFile)
	require.NoError(t, err)

	in, err := os.ReadFile(producers.OutFile)
	require.NoError(t, err)
	var wrote smithyv1.LaunchToolResponse
	err = proto.Unmarshal(in, &wrote)
	require.NoError(t, err)
	expectedIssues := []*smithyv1.Issue{
		{
			Target:      "file://code/cfngoat/cfngoat.yaml:891-892",
			Type:        "CKV_SECRET_6",
			Title:       "Base64 High Entropy String",
			Severity:    smithyv1.Severity_SEVERITY_HIGH,
			Description: "MatchedRule: {\"id\":\"CKV_SECRET_6\",\"name\":\"Base64 High Entropy String\",\"shortDescription\":{\"text\":\"Base64 High Entropy String\"},\"fullDescription\":{\"text\":\"Base64 High Entropy String\"},\"defaultConfiguration\":{\"level\":\"error\"},\"help\":{\"text\":\"Base64 High Entropy String\\nResource: c00f1a6e4b20aa64691d50781b810756d6254b8e\"}} \n Message: Base64 High Entropy String",
		}, {
			Target:      "file://code/cfngoat/.github/workflows/checkov.yaml:1-1",
			Type:        "CKV2_GHA_1",
			Title:       "Ensure top-level permissions are not set to write-all",
			Severity:    smithyv1.Severity_SEVERITY_HIGH,
			Description: "MatchedRule: {\"id\":\"CKV2_GHA_1\",\"name\":\"Ensure top-level permissions are not set to write-all\",\"shortDescription\":{\"text\":\"Ensure top-level permissions are not set to write-all\"},\"fullDescription\":{\"text\":\"Ensure top-level permissions are not set to write-all\"},\"defaultConfiguration\":{\"level\":\"error\"},\"help\":{\"text\":\"Ensure top-level permissions are not set to write-all\\nResource: on(build)\"}} \n Message: Ensure top-level permissions are not set to write-all",
		}, {
			Target:      "file://code/cfngoat/.github/workflows/main.yaml:1-1",
			Type:        "CKV2_GHA_1",
			Title:       "Ensure top-level permissions are not set to write-all",
			Severity:    smithyv1.Severity_SEVERITY_HIGH,
			Description: "MatchedRule: {\"id\":\"CKV2_GHA_1\",\"name\":\"Ensure top-level permissions are not set to write-all\",\"shortDescription\":{\"text\":\"Ensure top-level permissions are not set to write-all\"},\"fullDescription\":{\"text\":\"Ensure top-level permissions are not set to write-all\"},\"defaultConfiguration\":{\"level\":\"error\"},\"help\":{\"text\":\"Ensure top-level permissions are not set to write-all\\nResource: on(build)\"}} \n Message: Ensure top-level permissions are not set to write-all",
		},
	}

	slices.SortFunc(wrote.Issues, func(a, b *smithyv1.Issue) int { return strings.Compare(a.Target, b.Target) })
	slices.SortFunc(expectedIssues, func(a, b *smithyv1.Issue) int { return strings.Compare(a.Target, b.Target) })
	require.Equal(t, len(wrote.Issues), len(expectedIssues))
	for i, expectedIssue := range expectedIssues {
		require.Equal(t, expectedIssue.Title, wrote.Issues[i].Title)
		require.Equal(t, expectedIssue.Description, wrote.Issues[i].Description)
		require.Equal(t, expectedIssue.Target, wrote.Issues[i].Target)
		require.Equal(t, expectedIssue.Severity, wrote.Issues[i].Severity)
	}
}

func TestRunCyclonedx(t *testing.T) {
	workspace, err := os.MkdirTemp("", "smithy")
	require.NoError(t, err)
	defer require.NoError(t, os.RemoveAll(workspace))

	producers.OutFile = filepath.Join(workspace, "out.pb")
	input, err := os.ReadFile(cyclonedxInputPath)
	require.NoError(t, err)

	target := "pkg:my/awesome/package"
	require.NoError(t, run(input, target))

	_, err = os.Stat(producers.OutFile)
	require.NoError(t, err)

	in, err := os.ReadFile(producers.OutFile)
	require.NoError(t, err)
	var wrote smithyv1.LaunchToolResponse
	err = proto.Unmarshal(in, &wrote)
	require.NoError(t, err)
	sbom := string(input)

	var expectedBom cyclonedx.BOM
	var actualBom cyclonedx.BOM
	require.NoError(t, json.Unmarshal([]byte(sbom), &expectedBom))
	require.NoError(t, json.Unmarshal([]byte(*wrote.Issues[0].CycloneDXSBOM), &actualBom))

	require.Equal(t, 1, len(wrote.Issues))
	require.Equal(t, expectedBom, actualBom)
}
