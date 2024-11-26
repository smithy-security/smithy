package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

type CapturingHandler struct {
	mu   sync.Mutex
	logs []slog.Record
}

func (h *CapturingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, r.Clone())
	return nil
}

func (h *CapturingHandler) Logs() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), h.logs...)
}

func (h *CapturingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (h *CapturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *CapturingHandler) WithGroup(name string) slog.Handler {
	return h
}

func ptr[T any](v T) *T {
	return &v
}

func TestJsonLogger_Report(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		now         = time.Now().Unix()
		logger      = slog.New(&CapturingHandler{})
		vulns       = []*ocsf.VulnerabilityFinding{
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

	slog.SetDefault(logger)
	defer cancel()

	t.Run("it logs correctly 3 findings", func(t *testing.T) {
		require.NoError(
			t,
			Main(
				ctx,
				component.RunnerWithLogger(logger),
				component.RunnerWithStorer("local", nil),
			),
		)
	})
}
