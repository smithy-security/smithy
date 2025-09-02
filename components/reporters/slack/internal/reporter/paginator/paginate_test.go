package paginator

import (
	"fmt"

	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/pkg/utils"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func getTestData(numFindings, numVulnerabilities int) []*vf.VulnerabilityFinding {
	findings := make([]*vf.VulnerabilityFinding, numFindings)

	for i := 0; i < numFindings; i++ {
		dataSourceRepo := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      fmt.Sprintf("util/middleware/middleware_%d.go", i),
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine:   uint32(70 + i),
					EndLine:     uint32(76 + i),
					StartColumn: 4,
					EndColumn:   4,
				},
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: fmt.Sprintf("https://github.com/0c34/govwa/repo_%d", i),
				Reference:     fmt.Sprintf("branch_%d", i),
			},
		}

		dataSourceRepoJson, _ := protojson.Marshal(dataSourceRepo)

		vulnerabilities := make([]*ocsf.Vulnerability, numVulnerabilities)
		for j := 0; j < numVulnerabilities; j++ {
			vulnerabilities[j] = &ocsf.Vulnerability{
				Title:      utils.Ptr(fmt.Sprintf("Vulnerability %d-%d", i, j)),
				Desc:       utils.Ptr(fmt.Sprintf("Description %d-%d", i, j)),
				Severity:   utils.Ptr(fmt.Sprintf("SEVERITY_ID_%d", j)),
				VendorName: utils.Ptr(fmt.Sprintf("vendor_%d", j)),
				Cve: &ocsf.Cve{
					Uid:  fmt.Sprintf("CVE-2022-%04d", i*100+j),
					Desc: utils.Ptr(fmt.Sprintf("CVE Description %d-%d", i, j)),
				},
				Cwe: &ocsf.Cwe{
					Caption: utils.Ptr(fmt.Sprintf("CWE-%d", 79+j)),
					SrcUrl:  utils.Ptr(fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", 79+j)),
				},
			}
		}

		findings[i] = &vf.VulnerabilityFinding{
			ID: uint64(i),
			Finding: &ocsf.VulnerabilityFinding{
				FindingInfo: &ocsf.FindingInfo{
					DataSources: []string{
						string(dataSourceRepoJson),
					},
				},
				ConfidenceId:    utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Confidence:      utils.Ptr(fmt.Sprintf("High-%d", i)),
				SeverityId:      ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
				Severity:        utils.Ptr(fmt.Sprintf("SEVERITY_ID_%d", i)),
				Vulnerabilities: vulnerabilities,
				Message:         utils.Ptr(fmt.Sprintf("Test message %d", i)),
			},
		}
	}

	return findings
}

func TestStreamObjects_BasicPagination(t *testing.T) {
	findings := getTestData(2, 3) // 2 findings, each with 3 vulnerabilities
	pageSize := 4

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 2, len(batches))    // Expect 2 batches
	assert.Equal(t, 4, len(batches[0])) // First batch should have 4 items
	assert.Equal(t, 2, len(batches[1])) // Second batch should have 2 items
}

func TestStreamObjects_EmptyFindings(t *testing.T) {
	findings := getTestData(0, 0) // No findings
	pageSize := 5

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 0, len(batches)) // Expect no batches
}

func TestStreamObjects_NilFinding(t *testing.T) {
	findings := []*vf.VulnerabilityFinding{nil} // Single nil finding
	pageSize := 3

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 0, len(batches)) // Expect no batches
}

func TestStreamObjects_PageSizeLargerThanData(t *testing.T) {
	findings := getTestData(1, 2) // 1 finding with 2 vulnerabilities
	pageSize := 10

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 1, len(batches))    // Expect 1 batch
	assert.Equal(t, 2, len(batches[0])) // Batch should have 2 items
}

func TestStreamObjects_PageSizeOne(t *testing.T) {
	findings := getTestData(1, 3) // 1 finding with 3 vulnerabilities
	pageSize := 1

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 3, len(batches)) // Expect 3 batches
	for _, batch := range batches {
		assert.Equal(t, 1, len(batch)) // Each batch should have 1 item
	}
}

func TestStreamObjects_LastBatchIncomplete(t *testing.T) {
	findings := getTestData(1, 5) // 1 finding with 5 vulnerabilities
	pageSize := 3

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 2, len(batches))    // Expect 2 batches
	assert.Equal(t, 3, len(batches[0])) // First batch should have 3 items
	assert.Equal(t, 2, len(batches[1])) // Second batch should have 2 items
}

func TestStreamObjects_NilVulnerabilities(t *testing.T) {
	findings := getTestData(2, 0) // 2 findings, each with no vulnerabilities
	pageSize := 2

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	assert.Equal(t, 0, len(batches)) // Expect no batches
}
func TestStreamObjects_LargeNumberOfVulnerabilities(t *testing.T) {
	findings := getTestData(1000, 100) // 1000 findings, each with 100 vulnerabilities
	pageSize := 500

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	expectedTotalItems := 1000 * 100
	expectedBatches := (expectedTotalItems + pageSize - 1) / pageSize // Ceiling division

	assert.Equal(t, expectedBatches, len(batches)) // Verify the number of batches
	totalItems := 0
	for _, batch := range batches {
		totalItems += len(batch)
		assert.LessOrEqual(t, len(batch), pageSize) // Each batch should not exceed pageSize
	}
	assert.Equal(t, expectedTotalItems, totalItems) // Verify total items processed
}

func TestStreamObjects_LargeNumberOfFindings(t *testing.T) {
	findings := getTestData(10000, 1) // 10,000 findings, each with 1 vulnerability
	pageSize := 1000

	ch := StreamObjects(findings, pageSize)

	var batches [][]ObjectPair
	for batch := range ch {
		batches = append(batches, batch)
	}

	expectedTotalItems := 10000 * 1
	expectedBatches := (expectedTotalItems + pageSize - 1) / pageSize // Ceiling division

	assert.Equal(t, expectedBatches, len(batches)) // Verify the number of batches
	totalItems := 0
	for _, batch := range batches {
		totalItems += len(batch)
		assert.LessOrEqual(t, len(batch), pageSize) // Each batch should not exceed pageSize
	}
	assert.Equal(t, expectedTotalItems, totalItems) // Verify total items processed
}
