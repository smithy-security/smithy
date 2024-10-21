package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/enrichers"
)

const (
	// numFindings         = 20.
	expectedNumFindings = 5 // we have 5 distinct uuids
	defaultPolicy       = "cGFja2FnZSBleGFtcGxlLnBvbGljeVNhdAoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgPXRydWUgewogICAgcHJpbnQoaW5wdXQpCiAgICBjaGVja19zZXZlcml0eQp9CgpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfTE9XIgp9CgpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfSElHSCIKfQpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfTUVESVVNIgp9Cg=="
)

func setupRegoServer(t *testing.T) *httptest.Server {
	// setup server
	expected := "{}"
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type bod map[string]interface{}
		var body bod

		if strings.Contains(r.URL.String(), "/v1/policies") {
			_, err := fmt.Fprintf(w, "{}")
			require.NoError(t, err)
		}

		if strings.Contains(r.URL.String(), "/v1/data") {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			if strings.Contains(fmt.Sprintf("%#v\n ", body), "SEVERITY_CRITICAL") {
				_, err := fmt.Fprintf(w, "{\"result\":{\"allow\":false}}")
				require.NoError(t, err)
			} else {
				_, err := fmt.Fprintf(w, "{\"result\":{\"allow\":true}}")
				require.NoError(t, err)
			}
		}

		_, err := fmt.Fprint(w, expected)
		require.NoError(t, err)
	}))
	return svr
}

func genSampleIssues() []*v1.Issue {
	sev := []v1.Severity{
		v1.Severity_SEVERITY_CRITICAL,
		v1.Severity_SEVERITY_HIGH,
		v1.Severity_SEVERITY_MEDIUM,
		v1.Severity_SEVERITY_LOW,
		v1.Severity_SEVERITY_INFO,
	}
	raw := make([]*v1.Issue, expectedNumFindings)
	for i := 0; i < expectedNumFindings; i++ {
		raw[i] = &v1.Issue{
			Target:      fmt.Sprintf("%d some/target", i),
			Type:        fmt.Sprintf("%d some type", i),
			Title:       fmt.Sprintf("%d /some/target is vulnerable", i),
			Severity:    sev[i%len(sev)],
			Cvss:        float64(i),
			Confidence:  v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("%d foo bar", i),
			Cve:         "CVE-2017-11770",
			Uuid:        uuid.New().String(),
		}
	}
	return raw
}

func TestParseIssues(t *testing.T) {
	indir, outdir := enrichers.SetupIODirs(t)

	rawIssues := genSampleIssues()

	id := uuid.New()
	scanUUUID := id.String()
	startTime, _ := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
	orig := v1.LaunchToolResponse{
		Issues:   rawIssues,
		ToolName: "policySat",
		ScanInfo: &v1.ScanInfo{
			ScanUuid:      scanUUUID,
			ScanStartTime: timestamppb.New(startTime),
		},
	}
	// write sample raw issues in mktemp
	out, err := proto.Marshal(&orig)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indir+"/policySat.tagged.pb", out, 0o600))
	enrichers.SetReadPathForTests(indir)
	enrichers.SetWritePathForTests(outdir)
	policy = "cGFja2FnZSBleGFtcGxlLnBvbGljeVNhdAoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgPXRydWUgewogICAgcHJpbnQoaW5wdXQpCiAgICBjaGVja19zZXZlcml0eQp9CgpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfTE9XIgp9CgpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfSElHSCIKfQpjaGVja19zZXZlcml0eSB7CiAgICBpbnB1dC5zZXZlcml0eSA9PSAiU0VWRVJJVFlfTUVESVVNIgp9Cg=="

	svr := setupRegoServer(t)
	defer svr.Close()

	regoServer = svr.URL
	policy = defaultPolicy
	require.NoError(t, run())

	assert.FileExists(t, outdir+"/policySat.policy.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(outdir + "/policySat.policy.enriched.pb")
	require.NoError(t, err)

	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	//  ensure every finding has a policy decision and that for every finding the handler was called once
	for _, finding := range res.Issues {
		if finding.RawIssue.Severity != v1.Severity_SEVERITY_CRITICAL {
			assert.Contains(t, fmt.Sprintf("%#v\n", finding.Annotations), "\"Policy Pass: example/policySat\":\"true\"")
		}
	}
}

func TestHandlesZeroFindings(t *testing.T) {
	indir, outdir := enrichers.SetupIODirs(t)

	mockLaunchToolResponses := enrichers.GetEmptyLaunchToolResponse(t)

	for i, r := range mockLaunchToolResponses {
		// Write sample enriched responses to indir
		encodedProto, err := proto.Marshal(r)
		require.NoError(t, err)
		rwPermission600 := os.FileMode(0o600)

		require.NoError(t, os.WriteFile(fmt.Sprintf("%s/input_%d_%s.tagged.pb", indir, i, r.ToolName), encodedProto, rwPermission600))
	}

	svr := setupRegoServer(t)
	defer svr.Close()

	// Launch the enricher
	regoServer = svr.URL
	enrichers.SetReadPathForTests(indir)
	enrichers.SetWritePathForTests(outdir)
	policy = defaultPolicy

	require.NoError(t, run())

	// Check there is something in our output directory
	files, err := os.ReadDir(outdir)
	require.NoError(t, err)
	assert.NotEmpty(t, files)
	assert.Len(t, files, 4)

	// Check that both of them are EnrichedLaunchToolResponse
	// and their Issue property is an empty list
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".raw.pb") {
			continue
		}

		encodedProto, err := os.ReadFile(fmt.Sprintf("%s/%s", outdir, f.Name()))
		require.NoError(t, err)

		output := &v1.EnrichedLaunchToolResponse{}
		require.NoError(t, proto.Unmarshal(encodedProto, output))

		assert.Empty(t, output.Issues)
	}
}
