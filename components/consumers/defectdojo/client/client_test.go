package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/consumers/defectdojo/types"
)

func TestDojoClient(t *testing.T) {
	called := false
	mockTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.RequestURI, "/users")
		called = true
		_, err := w.Write([]byte(`{"count":1,"next":null,"previous":null,"results":[{"id":1,"username":"admin","first_name":"Admin","last_name":"User","email":"admin@defectdojo.local","last_login":"2022-05-31T20:26:54.928778Z","is_active":true,"is_superuser":true}]}`))
		require.NoError(t, err)
	}))
	authToken := "foo"
	authUser := "bar"
	client, err := DojoClient(mockTS.URL, authToken, authUser)
	c := &Client{host: mockTS.URL, apiToken: authToken, user: authUser}
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, client, c)
}

func TestCreateFinding(t *testing.T) {
	called := false
	expected := `{"id":16,"notes":[],"test":1,"thread_id":0,"found_by":[0],"url":null,"tags":[],"push_to_jira":false,"vulnerability_ids":[],"title":"Test","date":"2022-06-01","sla_start_date":null,"cwe":0,"cvssv3":null,"cvssv3_score":null,"severity":"High","description":"td","mitigation":null,"impact":null,"steps_to_reproduce":null,"severity_justification":null,"references":null,"active":true,"verified":false,"false_p":false,"duplicate":false,"out_of_scope":false,"risk_accepted":false,"under_review":false,"last_status_update":"2022-06-01T11:49:32.336953Z","under_defect_review":false,"is_mitigated":false,"mitigated":null,"numerical_severity":"S1","last_reviewed":null,"param":null,"payload":null,"hash_code":"02d7bb216799db2d65b66fa94cc1b05b7c8a89a00be2f07b87b1cf6e58125c3b","line":null,"file_path":null,"component_name":null,"component_version":null,"static_finding":false,"dynamic_finding":true,"created":"2022-06-01T11:49:32.289174Z","scanner_confidence":null}`
	mockTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, r.Method, "POST")
		assert.Equal(t, r.RequestURI, "/findings")
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var actual, exp types.FindingCreateRequest
		exp = types.FindingCreateRequest{
			Test:              1,
			FoundBy:           []int32{0},
			Duplicate:         false,
			Title:             "title",
			FalseP:            false,
			Severity:          "High",
			Description:       "description",
			Active:            true,
			Verified:          false,
			Line:              1,
			NumericalSeverity: "C:I",
			FilePath:          "foo target",
			Tags:              []string{"tests"},
			Date:              "2006-01-02",
		}
		require.NoError(t, json.Unmarshal(b, &actual))
		assert.Equal(t, actual, exp)
		_, err = w.Write([]byte(expected))
		require.NoError(t, err)
	}))
	c := &Client{host: mockTs.URL, apiToken: "test", user: ""}
	_, err := c.CreateFinding("title",
		"description",
		"High",
		"foo target",
		"2006-01-02",
		"C:I",
		[]string{"tests"},
		1,
		1,
		0, 0, false, false, 3.9)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestCreateEngagement(t *testing.T) {
	called := false
	mockTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, r.Method, "POST")
		assert.Equal(t, r.RequestURI, "/engagements")
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var engagement types.EngagementRequest
		require.NoError(t, json.Unmarshal(b, &engagement))

		expectedEngagement := types.EngagementRequest{
			Tags:                      []string{"foo.git/somesha"},
			Name:                      "smithy scan foo",
			TargetStart:               "2022-06-01",
			TargetEnd:                 "2022-06-01",
			DeduplicationOnEngagement: true,
			Product:                   2,
		}
		assert.Equal(t, expectedEngagement, engagement)
		_, err = w.Write([]byte(`{"id":4,"tags":["foo.git/somesha"],"name":"smithy scan foo","description":null,"version":"string","first_contacted":null,"target_start":"2022-06-01","target_end":"2022-06-01","reason":null,"updated":"2022-06-01T16:29:18.965507Z","created":"2022-06-01T16:29:18.908694Z","active":true,"tracker":null,"test_strategy":null,"threat_model":true,"api_test":true,"pen_test":true,"check_list":true,"status":"","progress":"threat_model","tmodel_path":"none","done_testing":false,"engagement_type":"Interactive","build_id":"foo","commit_hash":null,"branch_tag":null,"source_code_management_uri":null,"deduplication_on_engagement":false,"lead":null,"requester":null,"preset":null,"report_type":null,"product":2,"build_server":null,"source_code_management_server":null,"orchestration_engine":null,"notes":[],"files":[],"risk_acceptance":[]}`))
		require.NoError(t, err)
	}))
	c := &Client{host: mockTs.URL, apiToken: "test", user: ""}
	_, err := c.CreateEngagement("smithy scan foo", "2022-06-01", []string{"foo.git/somesha"}, 2)
	require.NoError(t, err)
	assert.True(t, called)
}
