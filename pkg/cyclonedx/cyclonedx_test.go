package cyclonedx

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

func TestToSmithyLibrary(t *testing.T) {
	rawLibraryBOM, err := os.ReadFile("./testdata/libraryBOM.json")
	require.NoError(t, err)

	issues, err := ToSmithy(rawLibraryBOM, "json", "")
	require.NoError(t, err)

	libraryBOM := string(rawLibraryBOM)

	expectedIssues := []*v1.Issue{
		{
			Target:        "pkg:npm/juice-shop@11.1.2",
			Type:          "SBOM",
			Title:         "SBOM for pkg:npm/juice-shop@11.1.2",
			Severity:      v1.Severity_SEVERITY_INFO,
			CycloneDXSBOM: &libraryBOM,
		},
	}
	require.Equal(t, expectedIssues[0].Target, issues[0].Target)
	require.Equal(t, expectedIssues[0].Type, issues[0].Type)
	require.Equal(t, expectedIssues[0].Title, issues[0].Title)
	require.Equal(t, expectedIssues[0].Severity, issues[0].Severity)
	var sbom1, sbom2 map[string]any
	require.NoError(t, json.Unmarshal([]byte(*expectedIssues[0].CycloneDXSBOM), &sbom1))
	require.NoError(t, json.Unmarshal([]byte(*issues[0].CycloneDXSBOM), &sbom2))
	require.Equal(t, sbom1, sbom2)
}

func TestToSmithySaaSInfra(t *testing.T) {
	rawSaaSBOM, err := os.ReadFile("./testdata/saasBOM.json")
	require.NoError(t, err)

	issues, err := ToSmithy(rawSaaSBOM, "json", "")
	require.NoError(t, err)

	saasBOM := string(rawSaaSBOM)
	expectedIssues := []*v1.Issue{
		{
			Target:        "acme-application",
			Type:          "SBOM",
			Title:         "SBOM for acme-application",
			Severity:      v1.Severity_SEVERITY_INFO,
			CycloneDXSBOM: &saasBOM,
		},
	}
	require.Equal(t, expectedIssues[0].Target, issues[0].Target)
	require.Equal(t, expectedIssues[0].Type, issues[0].Type)
	require.Equal(t, expectedIssues[0].Title, issues[0].Title)
	require.Equal(t, expectedIssues[0].Severity, issues[0].Severity)

	var sbom1, sbom2 map[string]any
	require.NoError(t, json.Unmarshal([]byte(*expectedIssues[0].CycloneDXSBOM), &sbom1))
	require.NoError(t, json.Unmarshal([]byte(*issues[0].CycloneDXSBOM), &sbom2))
	require.Equal(t, sbom1, sbom2)
}

func TestToSmithyTargetOverride(t *testing.T) {
	rawSaaSBOM, err := os.ReadFile("./testdata/saasBOM.json")
	require.NoError(t, err)

	issues, err := ToSmithy(rawSaaSBOM, "json", "my-awesome-infra")
	require.NoError(t, err)

	saasBOM := string(rawSaaSBOM)
	expectedIssues := []*v1.Issue{
		{
			Target:        "my-awesome-infra",
			Type:          "SBOM",
			Title:         "SBOM for my-awesome-infra",
			Severity:      v1.Severity_SEVERITY_INFO,
			CycloneDXSBOM: &saasBOM,
		},
	}
	require.Equal(t, expectedIssues[0].Target, issues[0].Target)
	require.Equal(t, expectedIssues[0].Type, issues[0].Type)
	require.Equal(t, expectedIssues[0].Title, issues[0].Title)
	require.Equal(t, expectedIssues[0].Severity, issues[0].Severity)

	var sbom1, sbom2 map[string]any
	require.NoError(t, json.Unmarshal([]byte(*expectedIssues[0].CycloneDXSBOM), &sbom1))
	require.NoError(t, json.Unmarshal([]byte(*issues[0].CycloneDXSBOM), &sbom2))
	require.Equal(t, sbom1, sbom2)
}
