package main

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

func genSampleIssues() []*v1.Issue {
	issues := []*v1.Issue{{}}
	for i := 0; i < 5; i++ {
		newIssue := &v1.Issue{
			Target:      fmt.Sprintf("%d some/target", i),
			Type:        fmt.Sprintf("%d some type", i),
			Title:       fmt.Sprintf("%d /some/target is vulnerable", i),
			Severity:    v1.Severity_SEVERITY_HIGH,
			Cvss:        float64(i),
			Confidence:  v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("%d foo bar", i),
			Cve:         "CVE-2017-11770",
		}
		issues = append(issues, newIssue)
	}
	return issues
}

func TestParseIssues(t *testing.T) {
	// prepare
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	issues := genSampleIssues()
	id := uuid.New()
	scanUUUID := id.String()
	startTime, err := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	resp := v1.LaunchToolResponse{
		Issues:   issues,
		ToolName: "taggerSat",
		ScanInfo: &v1.ScanInfo{
			ScanUuid:      scanUUUID,
			ScanStartTime: timestamppb.New(startTime),
		},
	}

	// write sample raw issues in mktemp
	out, err := proto.Marshal(&resp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path.Join(dir, "/taggerSat.pb"), out, 0o600))

	readPath = dir
	writePath = dir

	run()

	assert.FileExists(t, dir+"/taggerSat.tagged.pb", "Tagged file was not created")

	// load *tagged.pb
	pbBytes, err := os.ReadFile(dir + "/taggerSat.tagged.pb")
	require.NoError(t, err)

	res := v1.LaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	// ensure every issue has a uuid populated
	for _, issue := range res.Issues {
		assert.NotEqual(t, issue.Uuid, "")
		assert.NotNil(t, issue.Uuid)
	}
}
