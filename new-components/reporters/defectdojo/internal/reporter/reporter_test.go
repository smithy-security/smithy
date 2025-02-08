package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/new-components/reporters/defectdojo/internal/client"
	"github.com/smithy-security/smithy/new-components/reporters/defectdojo/internal/types"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const (
	usersResponse       = `{  "count": 1,  "next": null,  "previous": null,  "results": [    {      "id": 1,      "username": "admin",      "first_name": "",      "last_name": "",      "email": "",      "date_joined": "2021-07-02T00:21:09.430000Z",      "last_login": "2025-02-07T14:27:22.922362Z",      "is_active": true,      "is_superuser": true,      "configuration_permissions": []    }  ]}`
	engagementsResponse = `{"id":9,"tags":[],"name":"test12345","description":null,"version":null,"first_contacted":null,"target_start":"2025-02-07","target_end":"2025-02-14","reason":null,"updated":"2025-02-07T15:54:31.724423Z","created":"2025-02-07T15:54:31.664610Z","active":true,"tracker":null,"test_strategy":null,"threat_model":true,"api_test":true,"pen_test":true,"check_list":true,"status":"","progress":"threat_model","tmodel_path":"none","done_testing":false,"engagement_type":"Interactive","build_id":null,"commit_hash":null,"branch_tag":null,"source_code_management_uri":null,"deduplication_on_engagement":false,"lead":null,"requester":null,"preset":null,"report_type":null,"product":4,"build_server":null,"source_code_management_server":null,"orchestration_engine":null,"notes":[],"files":[],"risk_acceptance":[]}`
	testResponse        = `{"id":21,"engagement":9,"notes":[],"tags":[],"scan_type":null,"title":"string","description":"string","target_start":"2025-02-07T16:21:29.750000Z","target_end":"2025-02-07T16:21:29.750000Z","estimated_time":null,"actual_time":null,"percent_complete":2147483647,"updated":"2025-02-07T16:25:38.609440Z","created":"2025-02-07T16:25:38.585715Z","version":"string","build_id":"string","commit_hash":"string","branch_tag":"string","lead":null,"test_type":1,"environment":null,"api_scan_configuration":null,"files": []}`
)

func TestDDReporter(t *testing.T) {
	t.Run("The config should initialize correctly", func(t *testing.T) {
		url := "http://example.com:1234/api/v2"
		user := "smithy"
		key := "some-key"
		productID := int32(1)
		require.NoError(t, os.Setenv("SMITHY_INSTANCE_ID", url))
		require.NoError(t, os.Setenv("DOJO_USER", user))
		require.NoError(t, os.Setenv("DOJO_API_KEY", key))
		require.NoError(t, os.Setenv("DOJO_API_URL", url))
		require.NoError(t, os.Setenv("DOJO_PRODUCT_ID", fmt.Sprintf("%d", productID)))

		conf, err := NewConf(nil)
		require.NoError(t, err)
		assert.Equal(t, url, conf.URL)
		assert.Equal(t, user, conf.User)
		assert.Equal(t, key, conf.Token)
		assert.Equal(t, productID, conf.ProductID)
	})
	t.Run("it should send to dd", func(t *testing.T) {
		expected := map[uint64]*ocsf.VulnerabilityFinding{}
		instanceID := uuid.New().String()
		user := "smithy"
		key := "some-key"
		productID := 1
		inputData, testCreateReqs, findingCreateReqs, engagementCreateReqs := createObjects(t, productID, instanceID)
		for _, dat := range inputData {
			id, err := strconv.ParseUint(dat.Finding.FindingInfo.Uid, 10, 64)
			require.NoError(t, err)
			expected[id] = dat.Finding
		}

		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			require.NoError(t, err)
			body, err := io.ReadAll(buf)
			w.WriteHeader(http.StatusOK)

			switch r.URL.Path {
			case "/api/v2/users":
				w.Write([]byte(usersResponse))
			case "/api/v2/engagements":
				require.Equal(t, r.Method, http.MethodPost)
				engagementCreateReq := &types.EngagementRequest{}
				require.NoError(t, json.Unmarshal(body, engagementCreateReq))
				assert.Contains(t, engagementCreateReqs, engagementCreateReq)
				w.Write([]byte(engagementsResponse))
			case "/api/v2/tests":
				require.Equal(t, r.Method, http.MethodPost)
				testCreateReq := &types.TestCreateRequest{}
				require.NoError(t, err)
				require.NoError(t, json.Unmarshal(body, testCreateReq))
				assert.Contains(t, testCreateReqs, testCreateReq)
				w.Write([]byte(testResponse))
			case "/api/v2/findings":
				require.Equal(t, r.Method, http.MethodPost)
				findingsCreateReq := &types.FindingCreateRequest{}
				require.NoError(t, err)
				require.NoError(t, json.Unmarshal(body, findingsCreateReq))
				assert.Contains(t, findingCreateReqs, findingsCreateReq)
				w.Write([]byte(testResponse))
			default:
				assert.Failf(t, "received request for unexpected url path %s", r.URL.Path)
			}
		}))
		defer svr.Close()
		require.NoError(t, os.Setenv("SMITHY_INSTANCE_ID", instanceID))
		require.NoError(t, os.Setenv("DOJO_USER", user))
		require.NoError(t, os.Setenv("DOJO_API_KEY", key))
		require.NoError(t, os.Setenv("DOJO_API_URL", svr.URL+"/api/v2"))
		require.NoError(t, os.Setenv("DOJO_PRODUCT_ID", fmt.Sprintf("%d", productID)))
		require.NoError(t, os.Setenv("DOJO_ISSUE_TEMPLATE", ""))

		conf, err := NewConf(nil)
		require.NoError(t, err)

		require.NoError(t, err)
		dClient, err := client.DojoClient(context.TODO(), svr.URL+"/api/v2", key, user)
		require.NoError(t, err)
		reporter, err := New(conf, dClient)
		require.NoError(t, reporter.Report(context.Background(), inputData))
	})
}

func ptr[T any](v T) *T {
	return &v
}

func getTestData(id, now int64, nowDT *timestamppb.Timestamp, filePath string) vf.VulnerabilityFinding {
	return vf.VulnerabilityFinding{
		ID: uint64(id),
		Finding: &ocsf.VulnerabilityFinding{
			StartTime:    &now,
			StartTimeDt:  nowDT,
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
			Status:     ptr("opened"),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					AffectedCode: []*ocsf.AffectedCode{
						{
							File: &ocsf.File{
								Path: ptr(filePath),
							},
							StartLine: ptr(int32(1)),
							EndLine:   ptr(int32(2)),
						},
					},
					Severity:   ptr(ocsf.VulnerabilityFinding_SeverityId_name[int32(ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL)]),
					Title:      ptr("this is vulnerable"),
					VendorName: ptr("unittests"),
					Desc:       ptr("asdfaf"),
					Cwe: &ocsf.Cwe{
						Uid:    "1",
						SrcUrl: ptr("https://issues.com/1"),
					},
				},
			},
		}}

}

func createObjects(t *testing.T, product int, scanID string) ([]*vf.VulnerabilityFinding, []*types.TestCreateRequest, []*types.FindingCreateRequest, []*types.EngagementRequest) {
	times, _ := time.Parse(time.RFC3339, "2023-01-19T18:09:06.370037788Z")
	now := timestamppb.New(times).AsTime().Unix()
	var input []*vf.VulnerabilityFinding
	var testRequests []*types.TestCreateRequest
	var findingsRequests []*types.FindingCreateRequest
	engagementRequests := []*types.EngagementRequest{
		{
			Tags:        []string{"SmithyScan", scanID},
			Name:        scanID,
			Description: "",
			TargetStart: times.Format(dojoTimeFormat), TargetEnd: times.Format(dojoTimeFormat),
			Status:                    "",
			DeduplicationOnEngagement: true, Product: int32(product),
		},
	}

	for i := 0; i <= 3; i++ {
		toolName := fmt.Sprintf("unittests-vendor-%d", i)
		test := &types.TestCreateRequest{
			Tags:        []string{"SmithyScan", scanID},
			Title:       toolName,
			TargetStart: times.Format(dojoTestTimeFormat),
			TargetEnd:   times.Format(dojoTestTimeFormat),
			TestType:    client.DojoTestType,
			Engagement:  9,
		}
		for j := 0; j <= 3%(i+1); j++ {
			duplicateTimes, _ := time.Parse(time.RFC3339, "2000-01-19T18:09:06.370037788Z")
			duplicateTimestamp := timestamppb.New(duplicateTimes)
			y := getTestData(int64(j), now, timestamppb.New(times), fmt.Sprintf("file/path/%d%dfile.foo", i, j))
			active := true
			duplicate := false
			if j%2 == 0 {
				y.Finding.Vulnerabilities[0].FirstSeenTime = ptr(duplicateTimestamp.AsTime().Unix())
				y.Finding.Count = ptr(int32(j))
				active = false
				duplicate = true
				y.Finding.Enrichments = append(y.Finding.Enrichments, &ocsf.Enrichment{
					Type: ptr(ocsffindinginfo.Enrichment_EnrichmentType_name[int32(ocsffindinginfo.Enrichment_ENRICHMENT_TYPE_DUPLICATION)]),
				})
			}
			y.Finding.Vulnerabilities[0].VendorName = &toolName
			input = append(input, &y)

			d, err := applyTemplate(&y, y.Finding.Vulnerabilities[0])
			require.NoError(t, err)

			findingsReq := &types.FindingCreateRequest{
				Tags:              []string{"SmithyScan", scanID, toolName},
				Title:             *y.Finding.Vulnerabilities[0].Title,
				Date:              times.Format(dojoTimeFormat),
				Severity:          severityToDojoSeverity(y.Finding.Vulnerabilities[0].Severity),
				FilePath:          fmt.Sprintf("%s:%d-%d", *y.Finding.Vulnerabilities[0].AffectedCode[0].File.Path, *y.Finding.Vulnerabilities[0].AffectedCode[0].StartLine, *y.Finding.Vulnerabilities[0].AffectedCode[0].EndLine),
				NumericalSeverity: severityIDToDojoNumericalSeverity(y.Finding.Vulnerabilities[0].Severity),
				FoundBy:           []int32{0},
				Description:       *d,
				Active:            active,
				Duplicate:         duplicate,
				Test:              21,
				Cwe:               1,
			}
			if j%2 == 0 {
				findingsReq.Active = false
				findingsReq.Duplicate = true
			}
			findingsRequests = append(findingsRequests, findingsReq)
		}
		testRequests = append(testRequests, test)
	}
	return input, testRequests, findingsRequests, engagementRequests
}
