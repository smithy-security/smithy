package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type (
	capturingLogger struct {
		logs   []string
		fields []slog.Attr
	}

	store struct {
		vulns []*ocsf.VulnerabilityFinding
	}
)

func (s *store) Close(ctx context.Context) error {
	return nil
}

func (s *store) Validate(finding *ocsf.VulnerabilityFinding) error {
	return nil
}

func (s *store) Read(ctx context.Context, instanceID string) ([]*ocsf.VulnerabilityFinding, error) {
	return s.vulns, nil
}

func (s *store) Update(ctx context.Context, instanceID string, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (s *store) Write(ctx context.Context, instanceID string, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (c *capturingLogger) capture(msg string, keyvals ...any) {
	if msg != "" {
		c.logs = append(c.logs, msg)
	}

	if len(keyvals) > 0 {
		newAttr := slog.Attr{}
		for idx, kv := range keyvals {
			attr, ok := kv.(slog.Attr)
			if ok {
				c.fields = append(c.fields, attr)
				continue
			}

			if idx%2 == 0 {
				newAttr.Key = kv.(string)
				continue
			}

			newAttr.Value = slog.AnyValue(kv)
			c.fields = append(c.fields, newAttr)
		}
	}
}

func (c *capturingLogger) Debug(msg string, keyvals ...any) {
	c.capture(msg, keyvals...)
}

func (c *capturingLogger) Info(msg string, keyvals ...any) {
	c.capture(msg, keyvals...)
}

func (c *capturingLogger) Warn(msg string, keyvals ...any) {
	c.capture(msg, keyvals...)
}

func (c *capturingLogger) Error(msg string, keyvals ...any) {
	c.capture(msg, keyvals...)
}

func (c *capturingLogger) With(args ...any) component.Logger {
	c.capture("", args...)
	return c
}

func ptr[T any](v T) *T {
	return &v
}

func TestJsonLogger_Report(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		now         = time.Now().Unix()
		logger      = &capturingLogger{}

		vulns = []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("MEDIUM"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
				Count:        ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime: &now,
					DataSources: []string{
						"/main.go",
					},
					Desc:          ptr("lots of hacks"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of issues",
					Uid:           "1",
				},
				Message: ptr("lots of hacks"),
				Resource: &ocsf.ResourceDetails{
					Uid: ptr(
						strings.Join([]string{
							"/main.go",
							"1",
							"1",
						},
							":",
						),
					),
					Data: &structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: "1",
						},
					},
				},
				RawData:    ptr(`{"issues" : []}`),
				Severity:   ptr("CRITICAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
				StartTime:  &now,
				Status:     ptr("opened"),
				Time:       now,
				TypeUid: int64(
					ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
						100 +
						ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
				),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							Uid:    "1",
							SrcUrl: ptr("https://issues.com/1"),
						},
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("HIGH"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        ptr(int32(2)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime: &now,
					DataSources: []string{
						"/internal/sketchy/sketch.go",
					},
					Desc:          ptr("stop writing hacky code"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of hacky code",
					Uid:           "2",
				},
				Message: ptr("lots of hacky code"),
				Resource: &ocsf.ResourceDetails{
					Uid: ptr(
						strings.Join([]string{
							"/internal/sketchy/sketch.go",
							"10",
							"1",
						},
							":",
						),
					),
					Data: &structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: "2",
						},
					},
				},
				RawData:    ptr(`{"issues" : [{"id": 2}]}`),
				Severity:   ptr("HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  &now,
				Status:     ptr("opened"),
				Time:       now,
				TypeUid: int64(
					ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
						100 +
						ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
				),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							Uid:    "2",
							SrcUrl: ptr("https://issues.com/2"),
						},
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr("LOW"),
				ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
				Count:        ptr(int32(3)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime: &now,
					DataSources: []string{
						"/internal/sketchy/hacks.go",
					},
					Desc:          ptr("stop writing hacks"),
					FirstSeenTime: &now,
					LastSeenTime:  &now,
					ModifiedTime:  &now,
					ProductUid:    ptr("gosec"),
					Title:         "You have lots of hacks",
					Uid:           "3",
				},
				Message: ptr("lots of hacks"),
				Resource: &ocsf.ResourceDetails{
					Uid: ptr(
						strings.Join([]string{
							"/internal/sketchy/hacks.go",
							"123",
							"13",
						},
							":",
						),
					),
					Data: &structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: "3",
						},
					},
				},
				RawData:    ptr(`{"issues" : [{"id": 3}]}`),
				Severity:   ptr("HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  &now,
				Status:     ptr("opened"),
				Time:       now,
				TypeUid: int64(
					ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
						100 +
						ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
				),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							Uid:    "3",
							SrcUrl: ptr("https://issues.com/3"),
						},
					},
				},
			},
		}
	)

	defer cancel()

	t.Run("it logs correctly 3 findings", func(t *testing.T) {
		require.NoError(
			t,
			Main(
				ctx,
				component.RunnerWithLogger(logger),
				//	 TODO: Andrea fix this when bumping SDK.
			),
		)
		require.NotEmpty(t, logger.logs)
		var numFindings int
		for _, l := range logger.logs {
			if l == "found finding" {
				numFindings++
			}
		}
		assert.Equal(t, 3, numFindings)

		var findings []*ocsf.VulnerabilityFinding
		for _, l := range logger.fields {
			if l.Key == "finding" {
				var finding ocsf.VulnerabilityFinding
				b := []byte(l.Value.String())
				require.NoError(t, protojson.Unmarshal(b, &finding))
				findings = append(findings, &finding)
			}
		}

		assert.Subset(t, vulns, findings)
	})
}
