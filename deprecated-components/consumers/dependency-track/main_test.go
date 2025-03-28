package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/cyclonedx"
)

func TestUploadBomsFromRaw(t *testing.T) {
	rawSaaSBOM, err := os.ReadFile("./testdata/saasBOM.json")
	require.NoError(t, err)
	// we marshal and unmarshal to remove pretty formatting
	bom := cdx.BOM{}
	err = json.Unmarshal(rawSaaSBOM, &bom)
	require.NoError(t, err)
	marshalledBom, err := json.Marshal(bom)
	require.NoError(t, err)

	projUUID := uuid.MustParse("7c78f6c9-b4b0-493c-a912-0bb0a4f221f1")
	expectedRequest := dtrack.BOMUploadRequest{
		ProjectName:    "test",
		ProjectUUID:    &projUUID,
		ProjectVersion: "2022-1",
		AutoCreate:     true,
		BOM:            string(marshalledBom),
	}

	//nolint:gosec
	expectedToken := "7c78f6c9-token"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(500 << 20)
		require.NoError(t, err)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, []string{expectedRequest.ProjectName}, r.MultipartForm.Value["projectName"])
		require.Equal(t, []string{expectedRequest.ProjectUUID.String()}, r.MultipartForm.Value["project"])
		require.Equal(t, []string{expectedRequest.ProjectVersion}, r.MultipartForm.Value["projectVersion"])
		require.Equal(t, []string{expectedRequest.BOM}, r.MultipartForm.Value["bom"])

		_, err = w.Write([]byte("{\"Token\":\"" + expectedToken + "\"}"))
		require.NoError(t, err)
	}))
	defer ts.Close()
	projectUUID = projUUID.String()
	apiKey = "test"
	projectName = "test"
	c, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey(apiKey))
	require.NoError(t, err)

	client = c
	issues, err := cyclonedx.ToSmithy(rawSaaSBOM, "json", "")

	require.NoError(t, err)
	ltr := v1.LaunchToolResponse{
		ToolName: "SAT",
		Issues:   issues,
	}
	tokens, err := uploadBOMsFromRaw([]*v1.LaunchToolResponse{&ltr})
	require.NoError(t, err)
	assert.Equal(t, tokens, []string{expectedToken})
}

func TestUploadBomsFromEnriched(t *testing.T) {
	projUUID := uuid.MustParse("7c78f6c9-b4b0-493c-a912-0bb0a4f221f1")
	rawSaaSBOM, err := os.ReadFile("./testdata/saasBOM.json")
	require.NoError(t, err)

	// we marshal and unmarshal to remove pretty formatting
	bom := cdx.BOM{}
	err = json.Unmarshal(rawSaaSBOM, &bom)
	require.NoError(t, err)
	marshalledBom, err := json.Marshal(bom)
	require.NoError(t, err)

	expectedRequest := dtrack.BOMUploadRequest{
		ProjectName:    "test",
		ProjectUUID:    &projUUID,
		ProjectVersion: "2022-1",
		AutoCreate:     true,
		BOM:            string(marshalledBom),
	}
	expectedToken := "7c78f6c9-token"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(500 << 20)
		require.NoError(t, err)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, []string{expectedRequest.ProjectName}, r.MultipartForm.Value["projectName"])
		require.Equal(t, []string{expectedRequest.ProjectUUID.String()}, r.MultipartForm.Value["project"])
		require.Equal(t, []string{expectedRequest.ProjectVersion}, r.MultipartForm.Value["projectVersion"])
		require.Equal(t, []string{expectedRequest.BOM}, r.MultipartForm.Value["bom"])

		_, err = w.Write([]byte("{\"Token\":\"" + expectedToken + "\"}"))
		require.NoError(t, err)
	}))
	defer ts.Close()

	projectUUID = projUUID.String()
	apiKey = "test"
	projectName = "test"
	c, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey(apiKey))
	require.NoError(t, err)

	client = c
	issues, err := cyclonedx.ToSmithy(rawSaaSBOM, "json", "")

	require.NoError(t, err)
	ltr := v1.LaunchToolResponse{
		ToolName: "SAT",
		Issues:   issues,
	}
	eltr := v1.EnrichedLaunchToolResponse{
		OriginalResults: &ltr,
		Issues: []*v1.EnrichedIssue{
			{RawIssue: issues[0]},
		},
	}
	tokens, err := uploadBOMSFromEnriched([]*v1.EnrichedLaunchToolResponse{&eltr})
	require.NoError(t, err)
	assert.Equal(t, tokens, []string{expectedToken})
}

func TestUploadBomsFromEnrichedWithOwners(t *testing.T) {
	projUUID := uuid.MustParse("7c78f6c9-b4b0-493c-a912-0bb0a4f221f1")
	rawSaaSBOM, err := os.ReadFile("./testdata/saasBOM.json")
	require.NoError(t, err)
	// we marshal and unmarshal to remove pretty formatting
	bom := cdx.BOM{}
	err = json.Unmarshal(rawSaaSBOM, &bom)
	require.NoError(t, err)
	marshalledBom, err := json.Marshal(bom)
	require.NoError(t, err)

	expectedRequest := dtrack.BOMUploadRequest{
		ProjectName:    "test",
		ProjectUUID:    &projUUID,
		ProjectVersion: "2022-1",
		AutoCreate:     true,
		BOM:            string(marshalledBom),
	}
	expectedProjectUpdate := dtrack.Project{
		UUID:       projUUID,
		Name:       "fooProj",
		PURL:       "pkg://npm/xyz/asdf@v1.2.2",
		Properties: []dtrack.ProjectProperty(nil),
		Tags: []dtrack.Tag{
			{Name: "foo:bar"},
			{Name: "Owner:foo"},
			{Name: "Owner:bar"},
		},
	}

	expectedToken := "7c78f6c9-token"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/api/v1/bom" {
			err := r.ParseMultipartForm(500 << 20)
			require.NoError(t, err)
			require.Equal(t, "POST", r.Method)
			require.Equal(t, []string{expectedRequest.ProjectName}, r.MultipartForm.Value["projectName"])
			require.Equal(t, []string{expectedRequest.ProjectUUID.String()}, r.MultipartForm.Value["project"])
			require.Equal(t, []string{expectedRequest.ProjectVersion}, r.MultipartForm.Value["projectVersion"])
			require.Equal(t, []string{expectedRequest.BOM}, r.MultipartForm.Value["bom"])

			_, err = w.Write([]byte("{\"Token\":\"" + expectedToken + "\"}"))
			require.NoError(t, err)
		} else if r.URL.String() == "/api/v1/project/7c78f6c9-b4b0-493c-a912-0bb0a4f221f1" {
			project := dtrack.Project{
				UUID: projUUID,
				Name: "fooProj",
				PURL: "pkg://npm/xyz/asdf@v1.2.2",
				Tags: []dtrack.Tag{{Name: "foo:bar"}, {Name: "Owner:foo"}},
			}
			res, err := json.Marshal(project)
			require.NoError(t, err)

			_, err = w.Write(res)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		} else if r.URL.String() == "/api/v1/project" && r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			var req dtrack.Project
			require.NoError(t, json.Unmarshal(body, &req))
			assert.Equal(t, req.Tags, expectedProjectUpdate.Tags)
		} else {
			assert.Fail(t, r.URL.String())
		}
	}))
	defer ts.Close()

	projectUUID = projUUID.String()
	apiKey = "test"
	projectName = "test"
	c, err := dtrack.NewClient(ts.URL, dtrack.WithAPIKey(apiKey))
	require.NoError(t, err)

	client = c
	issues, err := cyclonedx.ToSmithy(rawSaaSBOM, "json", "")
	require.NoError(t, err)

	ltr := v1.LaunchToolResponse{
		ToolName: "SAT",
		Issues:   issues,
	}
	eltr := v1.EnrichedLaunchToolResponse{
		OriginalResults: &ltr,
		Issues: []*v1.EnrichedIssue{
			{
				RawIssue: issues[0],
				Annotations: map[string]string{
					"Owner-0": "foo",
					"Owner-1": "bar",
				},
			},
		},
	}
	ownerAnnotation = "Owner"
	tokens, err := uploadBOMSFromEnriched([]*v1.EnrichedLaunchToolResponse{&eltr})
	require.NoError(t, err)
	assert.Equal(t, tokens, []string{expectedToken})
}
