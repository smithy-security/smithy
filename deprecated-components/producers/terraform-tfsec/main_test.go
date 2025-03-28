package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers/terraform-tfsec/types"
	"github.com/smithy-security/smithy/pkg/testutil"
)

func TestParseOut(t *testing.T) {
	f, err := testutil.CreateFile("tfsec_tests_vuln_code", code)
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f.Name())

	var results types.TfSecOut
	err = json.Unmarshal([]byte(fmt.Sprintf(exampleOutput, f.Name(), f.Name())), &results)
	require.NoError(t, err)
	issues, err := parseOut(results)
	require.NoError(t, err)
	expectedIssues := []*v1.Issue{
		{
			Target:      f.Name() + ":4-4",
			Type:        "aws-api-gateway-use-secure-tls-policy",
			Title:       "API Gateway domain name uses outdated SSL/TLS protocols.",
			Severity:    4,
			Confidence:  3,
			Description: "{\"rule_id\":\"AVD-AWS-0005\",\"long_id\":\"aws-api-gateway-use-secure-tls-policy\",\"rule_description\":\"API Gateway domain name uses outdated SSL/TLS protocols.\",\"rule_provider\":\"aws\",\"rule_service\":\"api-gateway\",\"impact\":\"Outdated SSL policies increase exposure to known vulnerabilities\",\"resolution\":\"Use the most modern TLS/SSL policies available\",\"links\":[\"https://aquasecurity.github.io/tfsec/latest/checks/aws/api-gateway/use-secure-tls-policy/\",\"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy\"],\"description\":\"Domain name is configured with an outdated TLS policy.\",\"severity\":\"HIGH\",\"warning\":false,\"status\":0,\"resource\":\"aws_api_gateway_domain_name.outdated_security_policy\",\"location\":{\"filename\":\"" + f.Name() + "\",\"start_line\":4,\"end_line\":4}}",
		},
		{
			Target:      f.Name() + ":3-3",
			Type:        "aws-api-gateway-use-secure-tls-policy",
			Title:       "API Gateway domain name uses outdated SSL/TLS protocols.",
			Severity:    4,
			Confidence:  3,
			Description: "{\"rule_id\":\"AVD-AWS-0005\",\"long_id\":\"aws-api-gateway-use-secure-tls-policy\",\"rule_description\":\"API Gateway domain name uses outdated SSL/TLS protocols.\",\"rule_provider\":\"aws\",\"rule_service\":\"api-gateway\",\"impact\":\"Outdated SSL policies increase exposure to known vulnerabilities\",\"resolution\":\"Use the most modern TLS/SSL policies available\",\"links\":[\"https://aquasecurity.github.io/tfsec/latest/checks/aws/api-gateway/use-secure-tls-policy/\",\"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy\"],\"description\":\"Domain name is configured with an outdated TLS policy.\",\"severity\":\"HIGH\",\"warning\":false,\"status\":0,\"resource\":\"aws_api_gateway_domain_name.empty_security_policy\",\"location\":{\"filename\":\"" + f.Name() + "\",\"start_line\":3,\"end_line\":3}}",
		},
	}

	found := 0
	assert.Equal(t, 2, len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Target == issue.Target {
				singleMatch++
				found++
				assert.Equal(t, singleMatch, 1) // assert no duplicates
				assert.EqualValues(t, expected.Type, issue.Type)
				assert.EqualValues(t, expected.Title, issue.Title)
				assert.EqualValues(t, expected.Severity, issue.Severity)
				assert.EqualValues(t, expected.Cvss, issue.Cvss)
				assert.EqualValues(t, expected.Confidence, issue.Confidence)
				assert.EqualValues(t, expected.Description, issue.Description)
			}
		}
	}
	assert.Equal(t, found, len(issues)) // assert everything has been found
}

var code = `resource "azurerm_sql_server" "positive4" {
	name                         = "sqlserver"
	resource_group_name          = azurerm_resource_group.example.name
	location                     = azurerm_resource_group.example.location
	version                      = "12.0"
	administrator_login          = "mradministrator"
	administrator_login_password = "thisIsDog11"

	extended_auditing_policy {
	  storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
	  storage_account_access_key  = azurerm_storage_account.example.primary_access_key
	  storage_account_access_key_is_secondary = true
	  retention_in_days                       = 20
	}
}`
var exampleOutput = `
{
	"results": [
		{
			"rule_id": "AVD-AWS-0005",
			"long_id": "aws-api-gateway-use-secure-tls-policy",
			
			"rule_description": "API Gateway domain name uses outdated SSL/TLS protocols.",
			
			"rule_provider": "aws",
			"rule_service": "api-gateway",
			"impact": "Outdated SSL policies increase exposure to known vulnerabilities",
			"resolution": "Use the most modern TLS/SSL policies available",
			"links": [
				"https://aquasecurity.github.io/tfsec/latest/checks/aws/api-gateway/use-secure-tls-policy/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy"
			],
			"description": "Domain name is configured with an outdated TLS policy.",
			"severity": "HIGH",
			"warning": false,
			"status": 0,
			"resource": "aws_api_gateway_domain_name.outdated_security_policy",
			"location": {
				"filename": "%s",
				"start_line": 4,
				"end_line": 4
			}
		},
		{
			"rule_id": "AVD-AWS-0005",
			"long_id": "aws-api-gateway-use-secure-tls-policy",
			"rule_description": "API Gateway domain name uses outdated SSL/TLS protocols.",
			"rule_provider": "aws",
			"rule_service": "api-gateway",
			"impact": "Outdated SSL policies increase exposure to known vulnerabilities",
			"resolution": "Use the most modern TLS/SSL policies available",
			"links": [
				"https://aquasecurity.github.io/tfsec/latest/checks/aws/api-gateway/use-secure-tls-policy/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy"
			],
			"description": "Domain name is configured with an outdated TLS policy.",
			"severity": "HIGH",
			"warning": false,
			"status": 0,
			"resource": "aws_api_gateway_domain_name.empty_security_policy",
			"location": {
				"filename": "%s",
				"start_line": 3,
				"end_line": 3
			}
		}]}`
