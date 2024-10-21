package templating

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

func Test_TemplateStringRaw(t *testing.T) {
	type args struct {
		inputTemplate string
		issue         *v1.Issue
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "template references some of of the issue",
			args: args{
				inputTemplate: "Smithy found '{{.Title}}' at '{{.Target}}', severity '{{.Severity}}'",
				issue: &v1.Issue{
					Target:      "/foo/bar/baz:32",
					Title:       "whoops, XSS!",
					Severity:    v1.Severity_SEVERITY_HIGH,
					Cvss:        3.2,
					Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
					Description: "this is a description",
					Source:      "github.com/foo/bar",
					Cve:         "CVE-2020-1111",
					Uuid:        "2d7d1bd6-f1a0-11ed-a05b-0242ac120003",
				},
			},
			want:    "Smithy found 'whoops, XSS!' at '/foo/bar/baz:32', severity 'SEVERITY_HIGH'",
			wantErr: false,
		},
		{
			name: "template references all of the issue",
			args: args{
				inputTemplate: "Smithy found '{{.Title}}' at '{{.Target}}', severity '{{.Severity}}', rule id: '{{.Type}}', CVSS '{{.Cvss}}' Confidence '{{.Confidence}}' Original Description: {{.Description}}, Cve {{.Cve}}",
				issue: &v1.Issue{
					Target:      "/foo/bar/baz:32",
					Title:       "whoops, XSS!",
					Severity:    v1.Severity_SEVERITY_HIGH,
					Cvss:        3.2,
					Confidence:  v1.Confidence_CONFIDENCE_UNSPECIFIED,
					Description: "this is a description",
					Source:      "github.com/foo/bar",
					Cve:         "CVE-2020-1111",
					Uuid:        "2d7d1bd6-f1a0-11ed-a05b-0242ac120003",
				},
			},
			want:    "Smithy found 'whoops, XSS!' at '/foo/bar/baz:32', severity 'SEVERITY_HIGH', rule id: '', CVSS '3.2' Confidence 'CONFIDENCE_UNSPECIFIED' Original Description: this is a description, Cve CVE-2020-1111",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TemplateStringRaw(tt.args.inputTemplate, tt.args.issue)
			if (err != nil) != tt.wantErr {
				t.Errorf("templateStringRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if *got != tt.want {
				t.Errorf("templateStringRaw() = '%s', want '%s'", *got, tt.want)
			}
		})
	}
}

func Test_TemplateStringEnriched(t *testing.T) {
	tstampFS, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53+01:00")
	require.NoError(t, err)
	firstSeen := timestamppb.New(tstampFS)
	tstampUAT, err := time.Parse(time.RFC3339, "2020-04-13T11:51:53+01:00")
	require.NoError(t, err)
	updatedAt := timestamppb.New(tstampUAT)

	type args struct {
		inputTemplate string
		issue         *v1.EnrichedIssue
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "template references all of the issue",
			args: args{
				inputTemplate: "Smithy found '{{.RawIssue.Title}}' at '{{.RawIssue.Target}}', severity '{{.RawIssue.Severity}}', rule id: '{{.RawIssue.Type}}', CVSS '{{.RawIssue.Cvss}}' Confidence '{{.RawIssue.Confidence}}' Original Description: {{.RawIssue.Description}}, Cve {{.RawIssue.Cve}},\n{{ range $key,$element := .Annotations }}{{$key}}:{{$element}}\n{{end}}",
				issue: &v1.EnrichedIssue{
					RawIssue: &v1.Issue{
						Target:      "/foo/bar/baz:32",
						Title:       "whoops, XSS!",
						Severity:    v1.Severity_SEVERITY_HIGH,
						Cvss:        3.2,
						Confidence:  v1.Confidence_CONFIDENCE_HIGH,
						Description: "this is a description",
						Source:      "github.com/foo/bar",
						Cve:         "CVE-2020-1111",
						Type:        "G101",
						Uuid:        "2d7d1bd6-f1a0-11ed-a05b-0242ac120003",
					},
					FirstSeen:     firstSeen,
					Count:         15,
					FalsePositive: false,
					UpdatedAt:     updatedAt,
					Hash:          "",
					Annotations:   map[string]string{"Policy X": "false", "Some Other Annotation": "value"},
				},
			},
			want:    "Smithy found 'whoops, XSS!' at '/foo/bar/baz:32', severity 'SEVERITY_HIGH', rule id: 'G101', CVSS '3.2' Confidence 'CONFIDENCE_HIGH' Original Description: this is a description, Cve CVE-2020-1111,\nPolicy X:false\nSome Other Annotation:value\n",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TemplateStringEnriched(tt.args.inputTemplate, tt.args.issue)
			if (err != nil) != tt.wantErr {
				t.Errorf("templateStringEnriched() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if *got != tt.want {
				t.Errorf("templateStringEnriched() = `%s`, want `%s`", *got, tt.want)
			}
		})
	}
}

func TestDescriptionOptions(t *testing.T) {
	acceptableTime, err := time.Parse(time.RFC3339, "2024-10-10T20:06:33Z")
	require.NoError(t, err)

	for _, tt := range []struct {
		name                  string
		option                enrichedIssueOption
		wantErr               bool
		expectedEnrichedIssue *enrichedIssue
	}{
		{
			name:    "zero startTime returns err",
			option:  EnrichedIssueWithScanStartTime(time.Time{}),
			wantErr: true,
		},
		{
			name:    "non zero startTime returns no err",
			option:  EnrichedIssueWithScanStartTime(acceptableTime),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				ScanStartTime: acceptableTime.Format(time.RFC3339),
			},
		},
		{
			name:    "zero firstFound returns err",
			option:  EnrichedIssueWithFirstFound(time.Time{}),
			wantErr: true,
		},
		{
			name:    "non zero firstFound returns no err",
			option:  EnrichedIssueWithFirstFound(acceptableTime),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				FirstFound: acceptableTime.Format(time.RFC3339),
			},
		},
		{
			name:    "empty tool name returns err",
			option:  EnrichedIssueWithToolName(""),
			wantErr: true,
		},
		{
			name:    "valid tool name returns no err",
			option:  EnrichedIssueWithToolName("some-tool"),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				ToolName: "some-tool",
			},
		},
		{
			name:    "empty confidence text returns err",
			option:  EnrichedIssueWithConfidenceText(""),
			wantErr: true,
		},
		{
			name:    "valid confidence text returns no err",
			option:  EnrichedIssueWithConfidenceText("conf-text-1"),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				ConfidenceText: "conf-text-1",
			},
		},
		{
			name:    "empty severity text returns err",
			option:  EnrichedIssueWithSeverityText(""),
			wantErr: true,
		},
		{
			name:    "valid severity text returns no err",
			option:  EnrichedIssueWithSeverityText("severity-text-1"),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				SeverityText: "severity-text-1",
			},
		},
		{
			name:    "0 count returns no err",
			option:  EnrichedIssueWithCount(0),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				Count: 0,
			},
		},
		{
			name:    "positive count returns no err",
			option:  EnrichedIssueWithCount(420),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				Count: 420,
			},
		},
		{
			name:    "empty scan ID returns err",
			option:  EnrichedIssueWithScanID(""),
			wantErr: true,
		},
		{
			name:    "valid scan id returns no err",
			option:  EnrichedIssueWithScanID("scan-1"),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				ScanID: "scan-1",
			},
		},
		{
			name:    "valid code scan annotation returns no err",
			option:  EnrichedIssueWithFixedCodeAnnotation("fixedCode"),
			wantErr: false,
			expectedEnrichedIssue: &enrichedIssue{
				FixedCodeAnnotation: "fixedCode",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var ei enrichedIssue
			if err := tt.option(&ei); tt.wantErr {
				require.Error(t, err)
				return
			}
			require.Equal(t, tt.expectedEnrichedIssue, &ei)
		})
	}
}
