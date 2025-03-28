package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"
	"github.com/smithy-security/smithy/pkg/cyclonedx"

	"github.com/smithy-security/smithy/deprecated-components/enrichers/depsdev/types"
)

const (
	license = "Foo License v0"
)

func genSampleIssues(t *testing.T) []*v1.Issue {
	id := uuid.New()

	bom, err := os.ReadFile("./testdata/sampleSBOM.json")
	require.NoError(t, err)

	sampleSBOM := string(bom)
	rI := &v1.Issue{
		Target:        "some/target",
		Type:          "some type",
		Title:         "/some/target sbom",
		Severity:      v1.Severity_SEVERITY_INFO,
		Cvss:          0,
		Confidence:    v1.Confidence_CONFIDENCE_INFO,
		Description:   "foo bar",
		Cve:           "",
		Uuid:          id.String(),
		CycloneDXSBOM: &sampleSBOM,
	}
	return []*v1.Issue{rI}
}

func prepareIssue(t *testing.T, produceEmptyIssues bool) string {
	// prepare
	dir, err := os.MkdirTemp("/tmp", "")
	require.NoError(t, err)

	var rawIssues []*v1.Issue
	if produceEmptyIssues {
		rawIssues = []*v1.Issue{}
	} else {
		rawIssues = genSampleIssues(t)
	}

	id := uuid.New()
	scanUUUID := id.String()
	startTime, _ := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
	orig := v1.LaunchToolResponse{
		Issues:   rawIssues,
		ToolName: "depsdevSAT",
		ScanInfo: &v1.ScanInfo{
			ScanUuid:      scanUUUID,
			ScanStartTime: timestamppb.New(startTime),
		},
	}
	// write sample raw issues in mktemp
	out, _ := proto.Marshal(&orig)
	require.NoError(t, os.WriteFile(dir+"/depsdevSAT.tagged.pb", out, 0o600))
	enrichers.SetReadPathForTests(dir)
	enrichers.SetWritePathForTests(dir)
	return dir
}

// TODO: add test for deps dev and scorecard stuff
func setup(t *testing.T, produceEmptyIssues bool) (string, *httptest.Server) {
	dir := prepareIssue(t, produceEmptyIssues)

	// setup server
	response := types.Response{
		Version: types.Version{
			Licenses: []string{license},
			Projects: []types.Project{
				{
					ScorecardV2: types.ScorecardV2{
						Date:  "irrelevant",
						Score: 5.5,
						Check: []types.Check{
							{
								Name:   "foo",
								Score:  2,
								Reason: "bar",
							},
						},
					},
				},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.String(), "/_/s/go/p/")
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	depsdevBaseURL = srv.URL
	return dir, srv
}

func TestParseIssuesDepsDevScoreCardInfoWritten(t *testing.T) {
	dir, srv := setup(t, false)
	defer srv.Close()
	scoreCardInfo = "true"

	// run enricher
	require.NoError(t, run())
	assert.FileExists(t, dir+"/depsdevSAT.deps-dev.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(dir + "/depsdevSAT.deps-dev.enriched.pb")
	require.NoError(t, err, "could not read enriched file")

	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	expectedProperties := []cdx.Property{
		{Name: "aquasecurity:trivy:PkgType", Value: "gomod"},
		{Name: "ScorecardScore", Value: "5.500000"},
		{Name: "ScorecardInfo", Value: "{\n\t\"date\": \"irrelevant\",\n\t\"check\": [\n\t\t{\n\t\t\t\"name\": \"foo\",\n\t\t\t\"score\": 2,\n\t\t\t\"reason\": \"bar\"\n\t\t}\n\t],\n\t\"score\": 5.5\n}"},
		{Name: "aquasecurity:trivy:PkgType", Value: "gomod"},
		{Name: "ScorecardScore", Value: "5.500000"},
		{Name: "ScorecardInfo", Value: "{\n\t\"date\": \"irrelevant\",\n\t\"check\": [\n\t\t{\n\t\t\t\"name\": \"foo\",\n\t\t\t\"score\": 2,\n\t\t\t\"reason\": \"bar\"\n\t\t}\n\t],\n\t\"score\": 5.5\n}"},
		{Name: "aquasecurity:trivy:PkgType", Value: "gomod"},
		{Name: "ScorecardScore", Value: "5.500000"},
		{Name: "ScorecardInfo", Value: "{\n\t\"date\": \"irrelevant\",\n\t\"check\": [\n\t\t{\n\t\t\t\"name\": \"foo\",\n\t\t\t\"score\": 2,\n\t\t\t\"reason\": \"bar\"\n\t\t}\n\t],\n\t\"score\": 5.5\n}"},
	}
	//  ensure every component has a license attached to it
	for _, finding := range res.Issues {
		bom, err := cyclonedx.FromSmithy(finding.RawIssue)
		require.NoError(t, err, "Could not read enriched cyclone dx info")

		properties := []cdx.Property{}

		for _, component := range *bom.Components {
			properties = append(properties, *component.Properties...)
		}
		assert.Equal(t, properties, expectedProperties)
	}
}

func TestParseIssuesDepsDevExternalReferenceLinksWritten(t *testing.T) {
	dir, srv := setup(t, false)
	defer srv.Close()

	// run enricher
	require.NoError(t, run())
	assert.FileExists(t, dir+"/depsdevSAT.deps-dev.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(dir + "/depsdevSAT.deps-dev.enriched.pb")
	require.NoError(t, err, "could not read enriched file")

	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	expectedExternalReferences := []cdx.ExternalReference{
		{
			URL:  fmt.Sprintf("%s/go/p/cloud.google.com%%2Fgo%%2Fcompute/v/v1.14.0", srv.URL),
			Type: "other",
		}, {
			URL:  fmt.Sprintf("%s/go/p/cloud.google.com%%2Fgo%%2Fcompute%%2Fmetadata/v/v0.2.3", srv.URL),
			Type: "other",
		}, {
			URL:  fmt.Sprintf("%s/go/p/github.com%%2FAzure%%2Fazure-pipeline-go/v/v0.2.3", srv.URL),
			Type: "other",
		},
	}
	//  ensure every component has a license attached to it
	for _, finding := range res.Issues {
		bom, err := cyclonedx.FromSmithy(finding.RawIssue)
		require.NoError(t, err, "Could not read enriched cyclone dx info")

		externalReferences := []cdx.ExternalReference{}

		for _, component := range *bom.Components {
			externalReferences = append(externalReferences, *component.ExternalReferences...)
		}
		assert.Equal(t, externalReferences, expectedExternalReferences)
	}
}

func TestParseIssuesLicensesWritten(t *testing.T) {
	dir, srv := setup(t, false)
	defer srv.Close()

	licensesInEvidence = "false"

	// run enricher
	require.NoError(t, run())
	assert.FileExists(t, dir+"/depsdevSAT.deps-dev.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(dir + "/depsdevSAT.deps-dev.enriched.pb")
	require.NoError(t, err, "could not read enriched file")
	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	//  ensure every component has a license attached to it
	for _, finding := range res.Issues {
		bom, err := cyclonedx.FromSmithy(finding.RawIssue)
		require.NoError(t, err, "Could not read enriched cyclone dx info")
		found := false
		for _, component := range *bom.Components {
			for _, lic := range *component.Licenses {
				found = true
				assert.Equal(t, lic.License.Name, license)
			}
		}
		assert.True(t, found)
	}
}

func TestParseIssuesLicensesWrittenAccurateLicenses(t *testing.T) {
	dir, srv := setup(t, false)
	defer srv.Close()
	licensesInEvidence = "true"

	require.NoError(t, run())
	assert.FileExists(t, dir+"/depsdevSAT.deps-dev.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(dir + "/depsdevSAT.deps-dev.enriched.pb")
	require.NoError(t, err, "could not read enriched file")

	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	//  ensure every component has a license attached to it
	for _, finding := range res.Issues {
		bom, err := cyclonedx.FromSmithy(finding.RawIssue)
		require.NoError(t, err, "Could not read enriched cyclone dx info")
		found := false
		for _, component := range *bom.Components {
			for _, lic := range *component.Evidence.Licenses {
				found = true
				assert.Equal(t, lic.License.Name, license)
			}
		}
		assert.True(t, found)
	}
}

func TestHandlesZeroFindings(t *testing.T) {
	dir, srv := setup(t, true) // true means produce empty issues
	defer srv.Close()

	require.NoError(t, run())
	assert.FileExists(t, dir+"/depsdevSAT.deps-dev.enriched.pb", "file was not created")

	// load *enriched.pb
	pbBytes, err := os.ReadFile(dir + "/depsdevSAT.deps-dev.enriched.pb")
	require.NoError(t, err, "could not read enriched file")

	res := v1.EnrichedLaunchToolResponse{}
	require.NoError(t, proto.Unmarshal(pbBytes, &res))

	assert.Empty(t, res.Issues)
}
