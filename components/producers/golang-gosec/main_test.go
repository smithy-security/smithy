package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var code = `func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var product Product
		if err := rows.Scan(&product.Id, &product.Name, &product.Category, &product.Price); err != nil {
			return nil, err
		}`

var gosecout = `
{
	"Issues": [
		{
			"severity": "MEDIUM",
			"confidence": "HIGH",
			"cwe": {
				"id": "10",
				"url": "https://cwe.mitre.org/data/definitions/10.html"
			},
			"rule_id": "G304",
			"details": "Potential file inclusion via variable",
			"file": "%s",
			"code": "ioutil.ReadFile(path)",
			"line": "2",
			"column": "44"
		}
	],
	"Stats": {
		"files": 1,
		"lines": 60,
		"nosec": 0,
		"found": 1
	}
}`

func TestParseIssues(t *testing.T) {
	f, err := testutil.CreateFile("gosec_tests_vuln_code.go", code)
	require.NoError(t, err)
	tempFileName := f.Name()

	defer func() {
		require.NoError(t, os.Remove(tempFileName))
	}()

	exampleOutput := fmt.Sprintf(gosecout, tempFileName)
	var results GoSecOut
	err = json.Unmarshal([]byte(exampleOutput), &results)
	require.NoError(t, err)

	issues, err := parseIssues(&results)
	require.NoError(t, err)

	expectedIssue := &v1.Issue{
		Target:         fmt.Sprintf("file://%s:2-2", tempFileName),
		Type:           "G304",
		Title:          "Potential file inclusion via variable",
		Severity:       v1.Severity_SEVERITY_MEDIUM,
		Cvss:           0.0,
		Cwe:            []int32{10},
		Confidence:     v1.Confidence_CONFIDENCE_HIGH,
		Description:    "ioutil.ReadFile(path)",
		ContextSegment: &code,
	}

	require.Equal(t, expectedIssue, issues[0])
}

func TestHandleLine(t *testing.T) {
	tc := []struct {
		name          string
		line          string
		expectedStart int
		expectedEnd   int
	}{
		{
			name:          "line-line",
			line:          "2-44",
			expectedStart: 2,
			expectedEnd:   44,
		},
		{
			name:          "line",
			line:          "2",
			expectedStart: 2,
			expectedEnd:   2,
		},
		{
			name:          "invalid",
			line:          "invalid",
			expectedStart: 0,
			expectedEnd:   0,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			start, end := handleLine(tt.line)
			assert.Equal(t, tt.expectedStart, start)
			assert.Equal(t, tt.expectedEnd, end)
		})
	}
}
