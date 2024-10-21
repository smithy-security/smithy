package enrichment

import (
	"fmt"
	"strings"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/assert"
)

func TestGetHash(t *testing.T) {
	expectedIssue := &v1.Issue{
		Target:     "pkg:golang/github.com/coreos/etcd@0.5.0-alpha.5",
		Type:       "Vulnerable Dependency",
		Title:      "[CVE-2018-1099]  Improper Input Validation",
		Source:     "git.foo.com/repo.git?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Severity:   v1.Severity_SEVERITY_MEDIUM,
		Cvss:       5.5,
		Confidence: v1.Confidence_CONFIDENCE_HIGH,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\n",
			"5.5", "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "CVE-2018-1099",
			"", "https://ossindex.sonatype.org/vuln/8a190129-526c-4ee0-b663-92f38139c165"),
		Cve: "123-321",
	}
	assert.Equal(t, GetHash(expectedIssue), "a551cc3e4c52124f3769a26d43b9b57bc5667d4ddd9689c6432f9144fbec305b")

	expectedIssue.Source = strings.NewReplacer("aa", "bc").Replace(expectedIssue.Source)
	// Test for regression on Bug where we would calculate ?ref=<> value for enrichment
	assert.Equal(t, GetHash(expectedIssue), "a551cc3e4c52124f3769a26d43b9b57bc5667d4ddd9689c6432f9144fbec305b")

	expectedIssue.Source = strings.NewReplacer("git.foo.com/repo.git", "https://example.com/foo/bar").Replace(expectedIssue.Source)
	assert.NotEqual(t, GetHash(expectedIssue), "3c73dcc2f7c647a4ff460249074a8d50")
}
