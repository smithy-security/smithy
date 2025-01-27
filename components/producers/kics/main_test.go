package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers/kics/types"
	"github.com/smithy-security/smithy/pkg/testutil"
)

func TestParseOut(t *testing.T) {
	expectedIssues := []*v1.Issue{
		{
			Target:      "sql_server_predictable_admin_account_name:10",
			Type:        "MissingAttribute",
			Title:       "Insecure Configurations azure_rm_sqlserver Create (or update) SQL Server2",
			Severity:    4,
			Description: "{\"query_name\":\"AD Admin Not Configured For SQL Server\",\"query_id\":\"b176e927-bbe2-44a6-a9c3-041417137e5f\",\"query_url\":\"https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlserver_module.html#parameter-ad_user\",\"severity\":\"HIGH\",\"platform\":\"Ansible\",\"cloud_provider\":\"AZURE\",\"category\":\"Insecure Configurations\",\"description\":\"The Active Directory Administrator is not configured for a SQL server\",\"description_id\":\"afa96f09\",\"files\":[{\"file_name\":\"sql_server_predictable_admin_account_name\",\"similarity_id\":\"819786035c5ea3943e303532e747fabac9f8beaddddfd6ecb863382481c50c0c\",\"line\":10,\"resource_type\":\"azure_rm_sqlserver\",\"resource_name\":\"Create (or update) SQL Server2\",\"issue_type\":\"MissingAttribute\",\"search_key\":\"name={{Create (or update) SQL Server2}}.{{azure_rm_sqlserver}}\",\"search_line\":0,\"search_value\":\"\",\"expected_value\":\"azure_rm_sqlserver.ad_user should be defined\",\"actual_value\":\"azure_rm_sqlserver.ad_user is undefined\"}]}",
		},
		{
			Target:      "ad_admin_not_configured_for_sql_server:3",
			Type:        "MissingAttribute",
			Title:       "Insecure Configurations azure_rm_sqlserver Create (or update) SQL Server",
			Severity:    4,
			Description: "{\"query_name\":\"AD Admin Not Configured For SQL Server\",\"query_id\":\"b176e927-bbe2-44a6-a9c3-041417137e5f\",\"query_url\":\"https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlserver_module.html#parameter-ad_user\",\"severity\":\"HIGH\",\"platform\":\"Ansible\",\"cloud_provider\":\"AZURE\",\"category\":\"Insecure Configurations\",\"description\":\"The Active Directory Administrator is not configured for a SQL server\",\"description_id\":\"afa96f09\",\"files\":[{\"file_name\":\"ad_admin_not_configured_for_sql_server\",\"similarity_id\":\"e2acb4c0c4afe11e1908953bb768bab35e0ca53d4d20bc6af02f1c5350cbe587\",\"line\":3,\"resource_type\":\"azure_rm_sqlserver\",\"resource_name\":\"Create (or update) SQL Server\",\"issue_type\":\"MissingAttribute\",\"search_key\":\"name={{Create (or update) SQL Server}}.{{azure_rm_sqlserver}}\",\"search_line\":0,\"search_value\":\"\",\"expected_value\":\"azure_rm_sqlserver.ad_user should be defined\",\"actual_value\":\"azure_rm_sqlserver.ad_user is undefined\"}]}",
		},
		{
			Target:      "small_msql_server_audit_retention:54",
			Type:        "MissingAttribute",
			Title:       "Insecure Configurations azurerm_sql_server sqlserver",
			Severity:    4,
			Description: "{\"query_name\":\"AD Admin Not Configured For SQL Server\",\"query_id\":\"a3a055d2-9a2e-4cc9-b9fb-12850a1a3a4b\",\"query_url\":\"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator\",\"severity\":\"HIGH\",\"platform\":\"Terraform\",\"cloud_provider\":\"AZURE\",\"category\":\"Insecure Configurations\",\"description\":\"The Active Directory Administrator is not configured for a SQL server\",\"description_id\":\"bccbda19\",\"files\":[{\"file_name\":\"small_msql_server_audit_retention\",\"similarity_id\":\"a34bdc92c802268f18d3d56d43da1744d74d2dcdb8de3ca74ea2a92471eb7f5e\",\"line\":54,\"resource_type\":\"azurerm_sql_server\",\"resource_name\":\"sqlserver\",\"issue_type\":\"MissingAttribute\",\"search_key\":\"azurerm_sql_server[positive4]\",\"search_line\":0,\"search_value\":\"\",\"expected_value\":\"A 'azurerm_sql_active_directory_administrator' should be defined for 'azurerm_sql_server[positive4]'\",\"actual_value\":\"A 'azurerm_sql_active_directory_administrator' is not defined for 'azurerm_sql_server[positive4]'\"}]}",
		},
		{
			Target:      "sql_server_predictable_admin_account_name:35",
			Type:        "MissingAttribute",
			Title:       "Insecure Configurations azurerm_sql_server mssqlserver",
			Severity:    4,
			Description: "{\"query_name\":\"AD Admin Not Configured For SQL Server\",\"query_id\":\"a3a055d2-9a2e-4cc9-b9fb-12850a1a3a4b\",\"query_url\":\"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator\",\"severity\":\"HIGH\",\"platform\":\"Terraform\",\"cloud_provider\":\"AZURE\",\"category\":\"Insecure Configurations\",\"description\":\"The Active Directory Administrator is not configured for a SQL server\",\"description_id\":\"bccbda19\",\"files\":[{\"file_name\":\"sql_server_predictable_admin_account_name\",\"similarity_id\":\"86e39f354b76020e5e4d3fa85469a87509ffff482eaada3567df0f873b1642de\",\"line\":35,\"resource_type\":\"azurerm_sql_server\",\"resource_name\":\"mssqlserver\",\"issue_type\":\"MissingAttribute\",\"search_key\":\"azurerm_sql_server[positive4]\",\"search_line\":0,\"search_value\":\"\",\"expected_value\":\"A 'azurerm_sql_active_directory_administrator' should be defined for 'azurerm_sql_server[positive4]'\",\"actual_value\":\"A 'azurerm_sql_active_directory_administrator' is not defined for 'azurerm_sql_server[positive4]'\"}]}",
		},
	}
	// setup relevant filenames
	for name, content := range dummyCode {
		f, err := testutil.CreateFile(name, content)
		if err != nil {
			t.Error(err)
		}
		defer os.Remove(f.Name())
		for i, iss := range expectedIssues {
			if strings.HasPrefix(iss.Target, name) {
				expectedIssues[i].Target = strings.Replace(iss.Target, name, f.Name(), -1)
				expectedIssues[i].Description = strings.Replace(iss.Description, name, f.Name(), -1)
				expectedIssues[i].ContextSegment = &content
			}
		}
		exampleOutput = strings.ReplaceAll(exampleOutput, name, f.Name())
	}

	var results types.KICSOut
	err := json.Unmarshal([]byte(exampleOutput), &results)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	issues, err := parseOut(results)
	require.NoError(t, err)

	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
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

var dummyCode = map[string]string{
	"sql_server_predictable_admin_account_name": `#this is a problematic code where the query should report a result(s)
	- name: Create (or update) SQL Server1
	  azure_rm_sqlserver:
		resource_group: myResourceGroup
		name: server_name1
		location: westus
		admin_username: ""
		admin_password: Testpasswordxyz12!
	- name: Create (or update) SQL Server2
	  azure_rm_sqlserver:
		resource_group: myResourceGroup
		name: server_name2
		location: westus
		admin_username:
		admin_password: Testpasswordxyz12!
	- name: Create (or update) SQL Server3
	  azure_rm_sqlserver:
		resource_group: myResourceGroup
		name: server_name3
		location: westus
		admin_username: admin
		admin_password: Testpasswordxyz12!`,
	"ad_admin_not_configured_for_sql_server": `- name: Create (or update) SQL Server
	azure_rm_sqlserver:
	  resource_group: myResourceGroup
	  name: server_name
	  location: westus
	  admin_username: mylogin
	  admin_password: Testpasswordxyz12!
	  ad_user: sqladmin`,
	"small_msql_server_audit_retention": `resource "azurerm_sql_database" "positive1" {
		name                = "myexamplesqldatabase"
		resource_group_name = azurerm_resource_group.example.name
		location            = "West US"
		server_name         = azurerm_sql_server.example.name
	  
		extended_auditing_policy {
		  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
		  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
		  storage_account_access_key_is_secondary = true
		}
	  
		tags = {
		  environment = "production"
		}
	  }
	  
	  resource "azurerm_sql_database" "positive2" {
		name                = "myexamplesqldatabase"
		resource_group_name = azurerm_resource_group.example.name
		location            = "West US"
		server_name         = azurerm_sql_server.example.name
	  
		extended_auditing_policy {
		  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
		  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
		  storage_account_access_key_is_secondary = true
		  retention_in_days                       = 90
		}
	  
		tags = {
		  environment = "production"
		}
	  }
	  
	  resource "azurerm_sql_database" "positive3" {
		name                = "myexamplesqldatabase"
		resource_group_name = azurerm_resource_group.example.name
		location            = "West US"
		server_name         = azurerm_sql_server.example.name
	  
		extended_auditing_policy {
		  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
		  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
		  storage_account_access_key_is_secondary = true
		  retention_in_days                       = 0
		}
	  
		tags = {
		  environment = "production"
		}
	  }
	  
	  resource "azurerm_sql_server" "positive4" {
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
	  }`,
}
var exampleOutput = `
{
	"kics_version": "v1.6.5",
	"files_scanned": 6871,
	"lines_scanned": 238272,
	"files_parsed": 6858,
	"lines_parsed": 238633,
	"files_failed_to_scan": 0,
	"queries_total": 2441,
	"queries_failed_to_execute": 0,
	"queries_failed_to_compute_similarity_id": 0,
	"scan_id": "console",
	"severity_counters": {
		"HIGH": 15397,
		"INFO": 6131,
		"LOW": 10852,
		"MEDIUM": 36628,
		"TRACE": 0
	},
	"total_counter": 69008,
	"total_bom_resources": 0,
	"start": "2022-11-30T16:37:35.819129687Z",
	"end": "2022-11-30T16:43:36.55869707Z",
	"paths": [
		"/code"
	],
	"queries": [
		{
			"query_name": "AD Admin Not Configured For SQL Server",
			"query_id": "b176e927-bbe2-44a6-a9c3-041417137e5f",
			"query_url": "https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlserver_module.html#parameter-ad_user",
			"severity": "HIGH",
			"platform": "Ansible",
			"cloud_provider": "AZURE",
			"category": "Insecure Configurations",
			"description": "The Active Directory Administrator is not configured for a SQL server",
			"description_id": "afa96f09",
			"files": [
				{
					"file_name": "sql_server_predictable_admin_account_name",
					"similarity_id": "819786035c5ea3943e303532e747fabac9f8beaddddfd6ecb863382481c50c0c",
					"line": 10,
					"resource_type": "azure_rm_sqlserver",
					"resource_name": "Create (or update) SQL Server2",
					"issue_type": "MissingAttribute",
					"search_key": "name={{Create (or update) SQL Server2}}.{{azure_rm_sqlserver}}",
					"search_line": 0,
					"search_value": "",
					"expected_value": "azure_rm_sqlserver.ad_user should be defined",
					"actual_value": "azure_rm_sqlserver.ad_user is undefined"
				},
				{
					"file_name": "ad_admin_not_configured_for_sql_server",
					"similarity_id": "e2acb4c0c4afe11e1908953bb768bab35e0ca53d4d20bc6af02f1c5350cbe587",
					"line": 3,
					"resource_type": "azure_rm_sqlserver",
					"resource_name": "Create (or update) SQL Server",
					"issue_type": "MissingAttribute",
					"search_key": "name={{Create (or update) SQL Server}}.{{azure_rm_sqlserver}}",
					"search_line": 0,
					"search_value": "",
					"expected_value": "azure_rm_sqlserver.ad_user should be defined",
					"actual_value": "azure_rm_sqlserver.ad_user is undefined"
				}
			]
		},
		{
			"query_name": "AD Admin Not Configured For SQL Server",
			"query_id": "a3a055d2-9a2e-4cc9-b9fb-12850a1a3a4b",
			"query_url": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator",
			"severity": "HIGH",
			"platform": "Terraform",
			"cloud_provider": "AZURE",
			"category": "Insecure Configurations",
			"description": "The Active Directory Administrator is not configured for a SQL server",
			"description_id": "bccbda19",
			"files": [
				{
					"file_name": "small_msql_server_audit_retention",
					"similarity_id": "a34bdc92c802268f18d3d56d43da1744d74d2dcdb8de3ca74ea2a92471eb7f5e",
					"line": 54,
					"resource_type": "azurerm_sql_server",
					"resource_name": "sqlserver",
					"issue_type": "MissingAttribute",
					"search_key": "azurerm_sql_server[positive4]",
					"search_line": 0,
					"search_value": "",
					"expected_value": "A 'azurerm_sql_active_directory_administrator' should be defined for 'azurerm_sql_server[positive4]'",
					"actual_value": "A 'azurerm_sql_active_directory_administrator' is not defined for 'azurerm_sql_server[positive4]'"
				},
				{
					"file_name": "sql_server_predictable_admin_account_name",
					"similarity_id": "86e39f354b76020e5e4d3fa85469a87509ffff482eaada3567df0f873b1642de",
					"line": 35,
					"resource_type": "azurerm_sql_server",
					"resource_name": "mssqlserver",
					"issue_type": "MissingAttribute",
					"search_key": "azurerm_sql_server[positive4]",
					"search_line": 0,
					"search_value": "",
					"expected_value": "A 'azurerm_sql_active_directory_administrator' should be defined for 'azurerm_sql_server[positive4]'",
					"actual_value": "A 'azurerm_sql_active_directory_administrator' is not defined for 'azurerm_sql_server[positive4]'"
				}
			]}]}`
