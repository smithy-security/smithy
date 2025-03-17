package enrichers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
)

// SetupIODirs creates temporary directories for input and output files
func SetupIODirs(t *testing.T) (indir, outdir string) {
	indir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	outdir, err = os.MkdirTemp("", "")
	require.NoError(t, err)

	return indir, outdir
}

// GetEmptyLaunchToolResponse returns a slice of LaunchToolResponse with no issues
func GetEmptyLaunchToolResponse(_ *testing.T) []*smithyv1.LaunchToolResponse {
	return []*smithyv1.LaunchToolResponse{
		{
			ToolName: "tool1",
			Issues:   []*smithyv1.Issue{},
		},
		{
			ToolName: "tool2",
			Issues:   []*smithyv1.Issue{},
		},
	}
}

// GetEmptyLaunchToolResponse returns a slice of LaunchToolResponse with no issues
func GetLaunchToolResponse(_ *testing.T) []*smithyv1.LaunchToolResponse {
	code := `this
					is
					some
					code`
	return []*smithyv1.LaunchToolResponse{
		{
			ToolName: "tool1",
			Issues: []*smithyv1.Issue{
				{
					Target:         "file:/a/b/c/d.php:1-2",
					Type:           "sometype",
					Title:          "this is a title",
					Severity:       smithyv1.Severity_SEVERITY_CRITICAL,
					Cvss:           1.0,
					Confidence:     smithyv1.Confidence_CONFIDENCE_CRITICAL,
					Description:    "this is a handy dandy description",
					Source:         "this is a source",
					Cve:            "CVE-2020-123",
					Uuid:           "d9681ae9-223b-4df8-a422-7b29bb917a36",
					Cwe:            []int32{123},
					ContextSegment: &code,
				},
				{
					Target:         "file:/a/b/c/d.go:2-3",
					Type:           "sometype1",
					Title:          "this is a title1",
					Severity:       smithyv1.Severity_SEVERITY_CRITICAL,
					Cvss:           1.0,
					Confidence:     smithyv1.Confidence_CONFIDENCE_CRITICAL,
					Description:    "this is a handy dandy description1",
					Source:         "this is a source1",
					Cve:            "CVE-2020-124",
					Uuid:           "a9681ae9-223b-4df8-a422-7b29bb917a36",
					Cwe:            []int32{123},
					ContextSegment: &code,
				},
			},
		},
		{
			ToolName: "tool2",
			Issues: []*smithyv1.Issue{
				{
					Target:         "file:/a/b/c/d.py:1-2",
					Type:           "sometype",
					Title:          "this is a title",
					Severity:       smithyv1.Severity_SEVERITY_CRITICAL,
					Cvss:           1.0,
					Confidence:     smithyv1.Confidence_CONFIDENCE_CRITICAL,
					Description:    "this is a handy dandy description",
					Source:         "this is a source",
					Cve:            "CVE-2020-123",
					Uuid:           "q9681ae9-223b-4df8-a422-7b29bb917a36",
					Cwe:            []int32{123},
					ContextSegment: &code,
				},
				{
					Target:         "file:/a/b/c/d.py:2-3",
					Type:           "sometype1",
					Title:          "this is a title1",
					Severity:       smithyv1.Severity_SEVERITY_CRITICAL,
					Cvss:           1.0,
					Confidence:     smithyv1.Confidence_CONFIDENCE_CRITICAL,
					Description:    "this is a handy dandy description1",
					Source:         "this is a source1",
					Cve:            "CVE-2020-124",
					Uuid:           "w9681ae9-223b-4df8-a422-7b29bb917a36",
					Cwe:            []int32{123},
					ContextSegment: &code,
				},
			},
		},
	}
}
