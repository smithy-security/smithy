package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/require"
)

var (
	want             = "OK"
	info             = `{"Version":{"Number":"8.1.0"}}`
	scanUUID         = "test-uuid"
	scanStartTime, _ = time.Parse(time.RFC3339, "2020-04-13 11:51:53+01:00")

	esIn, _ = json.Marshal(&esDocument{
		ScanStartTime:  scanStartTime,
		ScanID:         scanUUID,
		ToolName:       "es-unit-tests",
		Source:         "es-tests-source",
		Title:          "es-tests-title",
		Target:         "es-tests-target",
		Type:           "es-tests-type",
		Severity:       v1.Severity_SEVERITY_INFO,
		SeverityText:   "Info",
		CVSS:           0.01,
		Confidence:     v1.Confidence_CONFIDENCE_INFO,
		ConfidenceText: "Info",
		Description:    "es-tests-description",
		FirstFound:     scanStartTime,
		Count:          2,
		FalsePositive:  false,
		CVE:            "CVE-0000-99999",
	})
)

func TestEsPushBasicAuth(t *testing.T) {
	esIndex = "smithy-es-test"

	esStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)

		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusOK)

		if r.Method == http.MethodGet {
			uname, pass, ok := r.BasicAuth()
			require.Equal(t, uname, "foo")
			require.Equal(t, pass, "bar")
			require.Equal(t, ok, true)

			_, err = w.Write([]byte(info))
			require.NoError(t, err)
		} else if r.Method == http.MethodPost {
			// assert non authed operation (write results to index)
			require.Equal(t, buf.String(), string(esIn))
			require.Equal(t, r.RequestURI, "/"+esIndex+"/_doc")

			uname, pass, ok := r.BasicAuth()
			require.Equal(t, uname, "foo")
			require.Equal(t, pass, "bar")
			require.Equal(t, ok, true)

			_, err = w.Write([]byte(want))
			require.NoError(t, err)
		}
	}))
	defer esStub.Close()
	os.Setenv("ELASTICSEARCH_URL", esStub.URL)

	// basic auth ops
	basicAuthUser = "foo"
	basicAuthPass = "bar"
	client, err := getESClient()
	require.NoError(t, err)
	_, err = client.Index(esIndex, bytes.NewBuffer(esIn))
	require.NoError(t, err)
}

func TestEsPush(t *testing.T) {
	esStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)

		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, err = w.Write([]byte(info))
		} else if r.Method == http.MethodPost {
			// assert non authed operation (write results to index)
			require.Equal(t, buf.String(), string(esIn))
			require.Equal(t, r.RequestURI, "/"+esIndex+"/_doc")
			_, err = w.Write([]byte(want))
		}
		require.NoError(t, err)
	}))
	defer esStub.Close()
	os.Setenv("ELASTICSEARCH_URL", esStub.URL)
	client, err := getESClient()
	require.NoError(t, err)
	_, err = client.Index(esIndex, bytes.NewBuffer(esIn))
	require.NoError(t, err)
}
func TestEsPushAPIKey(t *testing.T) {
	esIndex = "smithy-es-test"

	esStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)

		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusOK)

		require.Equal(t, r.Header.Get("Authorization"), "APIKey foo")

		if r.Method == http.MethodGet {
			_, err = w.Write([]byte(info))
			require.NoError(t, err)
		} else if r.Method == http.MethodPost {
			// assert non authed operation (write results to index)
			require.Equal(t, buf.String(), string(esIn))
			require.Equal(t, r.RequestURI, "/"+esIndex+"/_doc")

			_, err = w.Write([]byte(want))
			require.NoError(t, err)
		}
	}))
	defer esStub.Close()
	os.Setenv("ELASTICSEARCH_URL", esStub.URL)

	// apikey ops
	esAPIKey = "foo"
	esCloudID = esStub.Config.Addr
	client, err := getESClient()
	require.NoError(t, err)
	_, err = client.Index(esIndex, bytes.NewBuffer(esIn))
	require.NoError(t, err)
}
