package reporter

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

func TestElasticsearchReporter(t *testing.T) {
	t.Run("The config should initialize correctly", func(t *testing.T) {
		url := "http://example.com:1234"
		index := "smithy"
		key := "some-key"
		require.NoError(t, os.Setenv("ELASTICSEARCH_URL", url))
		require.NoError(t, os.Setenv("ELASTICSEARCH_INDEX", index))
		require.NoError(t, os.Setenv("ELASTICSEARCH_API_KEY", key))

		conf, err := NewConf(nil)
		require.NoError(t, err)
		assert.Equal(t, url, conf.ElasticsearchURL)
		assert.Equal(t, index, conf.ElasticsearchIndex)
		assert.Equal(t, key, conf.ElasticsearchApiKey)
	})

	t.Run("it should send to elasticsearch", func(t *testing.T) {
		expected := map[uint64]*ocsf.VulnerabilityFinding{}
		data := getTestData(time.Now().Unix())
		for _, dat := range data {
			// out, err := protojson.Marshal(dat.Finding)
			// require.NoError(t, err)
			id, err := strconv.ParseUint(dat.Finding.FindingInfo.Uid, 10, 64)
			require.NoError(t, err)
			expected[id] = dat.Finding
		}
		index := "smithy"
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			require.NoError(t, err)

			w.Header().Set("X-Elastic-Product", "Elasticsearch")
			w.WriteHeader(http.StatusOK)

			if r.Method == http.MethodGet {
				_, err = w.Write([]byte(`{"Version":{"Number":"8.1.0"}}`))
				require.NoError(t, err)
			} else if r.Method == http.MethodPost {
				finding := ocsf.VulnerabilityFinding{}
				msg := buf.Bytes()
				err := protojson.Unmarshal(msg, &finding)
				require.NoError(t, err)
				id, err := strconv.ParseUint(finding.FindingInfo.Uid, 10, 64)
				require.NoError(t, err)
				assert.Equal(t, expected[id], &finding)
				require.Equal(t, r.RequestURI, "/"+index+"/_doc")

				_, err = w.Write([]byte("OK"))
				require.NoError(t, err)
			}
		}))
		defer svr.Close()
		require.NoError(t, os.Setenv("ELASTICSEARCH_URL", svr.URL))
		require.NoError(t, os.Setenv("ELASTICSEARCH_INDEX", index))
		require.NoError(t, os.Setenv("ELASTICSEARCH_API_KEY", "asdf"))
		conf, err := NewConf(nil)
		require.NoError(t, err)
		c, err := GetESClient(conf)
		require.NoError(t, err)
		reporter, err := NewElasticsearchLogger(conf, c)
		require.NoError(t, err)
		require.NoError(t, reporter.Report(context.Background(), data))
	})
}

func ptr[T any](v T) *T {
	return &v
}

func getTestData(now int64) []*vf.VulnerabilityFinding {
	vulns := []*ocsf.VulnerabilityFinding{
		{
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			Confidence:   ptr("MEDIUM"),
			ConfidenceId: ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
			Count:        ptr(int32(1)),
			Enrichments: []*ocsf.Enrichment{
				{
					Name:     "foo",
					Provider: ptr("foo-enricher"),
					Value:    "fooval",
				},
				{
					Name:     "bar",
					Provider: ptr("bar-enricher"),
					Value:    "barval",
				},
			},
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
				Uid:           "0",
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
				Uid:           "1",
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
				Uid:           "2",
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
	findings := []*vf.VulnerabilityFinding{
		{
			ID:      0,
			Finding: vulns[0],
		},
		{
			ID:      1,
			Finding: vulns[1],
		},
		{
			ID:      2,
			Finding: vulns[2],
		},
	}
	return findings
}
