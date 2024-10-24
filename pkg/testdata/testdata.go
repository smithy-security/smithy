package testdata

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1protos "github.com/smithy-security/smithy/api/proto/v1"
)

var (
	staticTime, _ = time.Parse(time.RFC3339, "Fri, 27 Sep 24 13:15:50 +0000")
	Issues        = []*v1protos.Issue{
		{
			Target:      "file://foo/bar/baz.go:1-1",
			Type:        "G456",
			Title:       "There is a `foo` type issue",
			Severity:    v1protos.Severity_SEVERITY_INFO,
			Cvss:        2.0,
			Confidence:  v1protos.Confidence_CONFIDENCE_HIGH,
			Description: "We found `foo` on bar",
			Source:      "git://github.com/x/z",
		},
		{
			Target:      "file://foo/bar/baz.go:2-10",
			Type:        "G457",
			Title:       "There is a `bar` type issue",
			Severity:    v1protos.Severity_SEVERITY_UNSPECIFIED,
			Cvss:        3.1,
			Confidence:  v1protos.Confidence_CONFIDENCE_CRITICAL,
			Description: "We found `bar` on bar",
			Source:      "git://github.com/w/e",
		},
		{
			Target:      "file://foo/bar/foobar.go",
			Type:        "G458",
			Title:       "There is a `foobar` type issue",
			Severity:    v1protos.Severity_SEVERITY_CRITICAL,
			Cvss:        3.1,
			Confidence:  v1protos.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: "We found `foobar` on bar",
			Source:      "git://github.com/q/w",
		},
	}
	LaunchToolResponse = v1protos.LaunchToolResponse{
		ScanInfo: &v1protos.ScanInfo{
			ScanUuid:      "e95e4ee9-f101-45d7-9917-34c74acf1919",
			ScanStartTime: timestamppb.New(staticTime),
			ScanTags: map[string]string{
				"unittests": "True",
			},
		},
		ToolName: "tests",
		Issues:   Issues,
	}
	EnrichedLaunchToolResponse = v1protos.EnrichedLaunchToolResponse{
		OriginalResults: &LaunchToolResponse,
		Issues: func() []*v1protos.EnrichedIssue {
			var ei []*v1protos.EnrichedIssue
			for c, i := range Issues {
				ei = append(ei, &v1protos.EnrichedIssue{RawIssue: i,
					Count: uint64(c),
					Annotations: map[string]string{
						"issueNum":  fmt.Sprintf("%d", c),
						"someOther": "Annotation",
					}})
			}
			return ei
		}(),
	}
)
