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

func TestParseIssues(t *testing.T) {
	f, err := testutil.CreateFile("brakeman_tests_vuln_code.rb", code)
	require.NoError(t, err)
	tempFileName := f.Name()

	defer func() {
		require.NoError(t, os.Remove(tempFileName))
	}()

	exampleOutput := fmt.Sprintf(brakemanOut, tempFileName, tempFileName)
	var results BrakemanOut
	err = json.Unmarshal([]byte(exampleOutput), &results)
	require.NoError(t, err)

	issues, err := parseIssues(&results)
	require.NoError(t, err)

	expectedIssues := []*v1.Issue{
		{
			Target:         fmt.Sprintf("file://%s:1-1", tempFileName),
			Type:           "SQL Injection:0",
			Title:          "Possible SQL injection",
			Severity:       v1.Severity_SEVERITY_UNSPECIFIED,
			Cvss:           0.0,
			Cwe:            []int32{89},
			Confidence:     v1.Confidence_CONFIDENCE_HIGH,
			Description:    "Possible SQL injection\nSQL Injection\n",
			ContextSegment: &code,
		},
		{
			Target:         fmt.Sprintf("file://%s:2-2", tempFileName),
			Type:           "Cross-Site Request Forgery:7",
			Title:          "protect_from_forgery should be called in ApplicationController",
			Severity:       v1.Severity_SEVERITY_UNSPECIFIED,
			Cvss:           0.0,
			Cwe:            []int32{352},
			Confidence:     v1.Confidence_CONFIDENCE_HIGH,
			Description:    "protect_from_forgery should be called in ApplicationController\nCross-Site Request Forgery\n",
			ContextSegment: &code,
		},
	}

	require.Equal(t, expectedIssues, issues)
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

// Not valid ruby but we are only checking for parsing of brakeman results
var code = `
User.find_by_sql(\"SELECT * FROM users WHERE email = '#{params[:email]}' AND password = '#{params[:password]}'\")
ApplicationController`
var brakemanOut = `
{
  "scan_info": {
    "app_path": "/code",
    "rails_version": "4.x",
    "security_warnings": 2,
    "start_time": "2024-09-16 14:54:55 +0000",
    "end_time": "2024-09-16 14:54:55 +0000",
    "duration": 0.267453374,
    "checks_performed": [
      "BasicAuth",
      "BasicAuthTimingAttack",
      "CSRFTokenForgeryCVE",
      "ContentTag",
      "CookieSerialization",
      "CreateWith",
      "CrossSiteScripting",
      "DefaultRoutes",
      "Deserialize",
      "DetailedExceptions",
      "DigestDoS",
      "DivideByZero",
      "DynamicFinders",
      "EOLRails",
      "EOLRuby",
      "EscapeFunction",
      "Evaluation",
      "Execute",
      "FileAccess",
      "FileDisclosure",
      "FilterSkipping",
      "ForceSSL",
      "ForgerySetting",
      "HeaderDoS",
      "I18nXSS",
      "JRubyXML",
      "JSONEncoding",
      "JSONEntityEscape",
      "JSONParsing",
      "LinkTo",
      "LinkToHref",
      "MailTo",
      "MassAssignment",
      "MimeTypeDoS",
      "ModelAttrAccessible",
      "ModelAttributes",
      "ModelSerialize",
      "NestedAttributes",
      "NestedAttributesBypass",
      "NumberToCurrency",
      "PageCachingCVE",
      "Pathname",
      "PermitAttributes",
      "QuoteTableName",
      "Ransack",
      "Redirect",
      "RegexDoS",
      "Render",
      "RenderDoS",
      "RenderInline",
      "ResponseSplitting",
      "ReverseTabnabbing",
      "RouteDoS",
      "SQL",
      "SQLCVEs",
      "SSLVerify",
      "SafeBufferManipulation",
      "SanitizeConfigCve",
      "SanitizeMethods",
      "Secrets",
      "SelectTag",
      "SelectVulnerability",
      "Send",
      "SendFile",
      "SessionManipulation",
      "SessionSettings",
      "SimpleFormat",
      "SingleQuotes",
      "SkipBeforeFilter",
      "SprocketsPathTraversal",
      "StripTags",
      "SymbolDoS",
      "SymbolDoSCVE",
      "TemplateInjection",
      "TranslateBug",
      "UnsafeReflection",
      "UnsafeReflectionMethods",
      "UnscopedFind",
      "ValidationRegex",
      "VerbConfusion",
      "WeakHash",
      "WeakRSAKey",
      "WithoutProtection",
      "XMLDoS",
      "YAMLParsing"
    ],
    "number_of_controllers": 4,
    "number_of_models": 2,
    "number_of_templates": 11,
    "ruby_version": "3.3.4",
    "brakeman_version": "6.2.1"
  },
  "warnings": [
    {
      "warning_type": "SQL Injection",
      "warning_code": 0,
      "fingerprint": "2377c284794a5ea965ede6303a2236ed4eb829642879477f30bdf94ad0f11054",
      "check_name": "SQL",
      "message": "Possible SQL injection",
      "file": "%s",
      "line": 1,
      "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
      "code": "User.find_by_sql(\"SELECT * FROM users WHERE email = '#{params[:email]}' AND password = '#{params[:password]}'\")",
      "render_path": null,
      "location": {
        "type": "method",
        "class": "SessionsController",
        "method": "create"
      },
      "user_input": "params[:email]",
      "confidence": "High",
      "cwe_id": [
        89
      ]
    },
    {
      "warning_type": "Cross-Site Request Forgery",
      "warning_code": 7,
      "fingerprint": "8a1e3382d5e2bbbf94c19f5ad1cb9355df95f9231f9f426803ac8005b4a63c0b",
      "check_name": "ForgerySetting",
      "message": "protect_from_forgery should be called in ApplicationController",
      "file": "%s",
      "line": 2,
      "link": "https://brakemanscanner.org/docs/warning_types/cross-site_request_forgery/",
      "code": null,
      "render_path": null,
      "location": {
        "type": "controller",
        "controller": "ApplicationController"
      },
      "user_input": null,
      "confidence": "High",
      "cwe_id": [
        352
      ]
    }
  ],
  "ignored_warnings": [

  ],
  "errors": [

  ],
  "obsolete": [

  ]
}
`
