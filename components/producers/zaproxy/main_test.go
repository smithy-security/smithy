package main

import (
	"encoding/json"
	"fmt"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers/zaproxy/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var riskcodetests = []struct {
	zapriskcode   string
	severityissue v1.Severity
}{
	{"0", v1.Severity_SEVERITY_INFO},
	{"1", v1.Severity_SEVERITY_LOW},
	{"2", v1.Severity_SEVERITY_MEDIUM},
	{"3", v1.Severity_SEVERITY_HIGH},
	{"4", v1.Severity_SEVERITY_CRITICAL},
	{"5", v1.Severity_SEVERITY_CRITICAL},
}

func TestZapRiskcodeToSmithySeverityParametrized(t *testing.T) {
	for _, riskcode := range riskcodetests {
		assert.EqualValues(t, riskcode.severityissue, riskcodeToSeverity(riskcode.zapriskcode))
	}
}

var confidencetests = []struct {
	zapconfidence   string
	confidenceissue v1.Confidence
}{
	{"0", v1.Confidence_CONFIDENCE_INFO},
	{"1", v1.Confidence_CONFIDENCE_LOW},
	{"2", v1.Confidence_CONFIDENCE_MEDIUM},
	{"3", v1.Confidence_CONFIDENCE_HIGH},
	{"4", v1.Confidence_CONFIDENCE_CRITICAL},
	{"5", v1.Confidence_CONFIDENCE_CRITICAL},
}

func TestZapConfidenceToSmithyConfidenceParametrized(t *testing.T) {
	for _, confidence := range confidencetests {
		assert.EqualValues(t, confidence.confidenceissue, zapconfidenceToConfidence(confidence.zapconfidence))
	}
}

func TestZapOutputWhenOneSiteAndOneAlert(t *testing.T) {
	var results types.ZapOut
	err := json.Unmarshal([]byte(exampleOutput1), &results)
	require.NoError(t, err)
	issues := parseOut(&results)
	expectedIssues := []*v1.Issue{
		{
			Target:     "https://thisisanexample.com",
			Type:       "16",
			Title:      "X-Content-Type-Options Header Missing",
			Severity:   v1.Severity_SEVERITY_LOW,
			Cvss:       0.0,
			Confidence: v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("Description: %s\nSolution: %s\nReference: %s\n",
				"<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>",
				"<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>",
				"<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx</p><p>https://owasp.org/www-community/Security_Headers</p>"),
		},
	}
	assert.Equal(t, len(expectedIssues), len(issues))

	for _, issue := range issues {
		for _, expected := range expectedIssues {
			assert.EqualValues(t, expected.Target, issue.Target)
			assert.EqualValues(t, expected.Type, issue.Type)
			assert.EqualValues(t, expected.Title, issue.Title)
			assert.EqualValues(t, expected.Severity, issue.Severity)
			assert.EqualValues(t, expected.Cvss, issue.Cvss)
			assert.EqualValues(t, expected.Confidence, issue.Confidence)
			assert.EqualValues(t, expected.Description, issue.Description)
		}
	}
}

func TestZapOutputWhenTwoSitesAndMultipleAlerts(t *testing.T) {
	var results types.ZapOut
	err := json.Unmarshal([]byte(exampleOutput2), &results)
	require.NoError(t, err)
	issues := parseOut(&results)
	expectedIssues := []*v1.Issue{
		{
			Target:     "https://thisisanexample.com",
			Type:       "16",
			Title:      "X-Content-Type-Options Header Missing",
			Severity:   v1.Severity_SEVERITY_LOW,
			Cvss:       0.0,
			Confidence: v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("Description: %s\nSolution: %s\nReference: %s\n",
				"<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>",
				"<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>",
				"<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx</p><p>https://owasp.org/www-community/Security_Headers</p>"),
		},
		{
			Target:     "https://thisisanexample.com",
			Type:       "16",
			Title:      "X-Frame-Options Header Not Set",
			Severity:   v1.Severity_SEVERITY_MEDIUM,
			Cvss:       0.0,
			Confidence: v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("Description: %s\nSolution: %s\nReference: %s\n",
				"<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.</p>",
				"<p>Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).</p>",
				"<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options</p>"),
		},
		{
			Target:     "https://thisithesecondexample.com",
			Type:       "16",
			Title:      "X-Content-Type-Options Header Missing",
			Severity:   v1.Severity_SEVERITY_LOW,
			Cvss:       0.0,
			Confidence: v1.Confidence_CONFIDENCE_MEDIUM,
			Description: fmt.Sprintf("Description: %s\nSolution: %s\nReference: %s\n",
				"<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>",
				"<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>",
				"<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx</p><p>https://owasp.org/www-community/Security_Headers</p>"),
		},
	}
	assert.Equal(t, len(expectedIssues), len(issues))
	for i, issue := range issues {
		assert.EqualValues(t, expectedIssues[i].Target, issue.Target)
		assert.EqualValues(t, expectedIssues[i].Type, issue.Type)
		assert.EqualValues(t, expectedIssues[i].Title, issue.Title)
		assert.EqualValues(t, expectedIssues[i].Severity, issue.Severity)
		assert.EqualValues(t, expectedIssues[i].Cvss, issue.Cvss)
		assert.EqualValues(t, expectedIssues[i].Confidence, issue.Confidence)
		assert.EqualValues(t, expectedIssues[i].Description, issue.Description)
	}
}

var exampleOutput1 = `{
    "@version": "2.10.0",
    "@generated": "Tue, 25 May 2021 15:19:04",
    "site": [
        {
            "@name": "https://thisisanexample.com",
            "@host": "thisisanexample.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {
                    "pluginid": "10021",
                    "alertRef": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "name": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "confidence": "2",
                    "riskdesc": "Low (Medium)",
                    "desc": "<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.<\/p>",
                    "instances": [
                        {
                            "uri": "https://thisisanexample.com/sso?SAMLRequest=lZLLbsIwEEX3fEWUfZ4ktFiBTKcG2vEGrdShz%2BhcHXw%3D%3D&RelayState=https%3A%2F%2Fthisisanexample.com%2F",
                            "method": "GET",
                            "param": "X-Content-Type-Options"
                        },
                        {
                            "uri": "https://thisisanexample.com/sso",
                            "method": "POST",
                            "param": "X-Content-Type-Options"
                        }
                    ],
                    "count": "2",
                    "solution": "<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.<\/p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.<\/p>",
                    "otherinfo": "<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.<\/p><p>At \"High\" threshold this scan rule will not alert on client or server error responses.<\/p>",
                    "reference": "<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx<\/p><p>https://owasp.org/www-community/Security_Headers<\/p>",
                    "cweid": "16",
                    "wascid": "15",
                    "sourceid": "3"
                }
            ]
        }
    ]
}`

var exampleOutput2 = ` {
    "@version": "2.10.0",
    "@generated": "Tue, 25 May 2021 15:19:04",
    "site": [
        {
            "@name": "https://thisisanexample.com",
            "@host": "thisisanexample.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {
                    "pluginid": "10021",
                    "alertRef": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "name": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "confidence": "2",
                    "riskdesc": "Low (Medium)",
                    "desc": "<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.<\/p>",
                    "instances": [
                        {
                            "uri": "https://thisisanexample.com/sso?SAMLRequest=lZLex2Or%2BkFZY5mBWYvUzhaTk9VtEFnmvCC9k09XiK9Xw%3D%3D&RelayState=https%3A%2F%2Fthisisanexample.com%2F",
                            "method": "GET",
                            "param": "X-Content-Type-Options"
                        },
                        {
                            "uri": "https://thisisanexample.com/sso",
                            "method": "POST",
                            "param": "X-Content-Type-Options"
                        }
                    ],
                    "count": "2",
                    "solution": "<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.<\/p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.<\/p>",
                    "otherinfo": "<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.<\/p><p>At \"High\" threshold this scan rule will not alert on client or server error responses.<\/p>",
                    "reference": "<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx<\/p><p>https://owasp.org/www-community/Security_Headers<\/p>",
                    "cweid": "16",
                    "wascid": "15",
                    "sourceid": "3"
                },
                {
                    "pluginid": "10020",
                    "alertRef": "10020",
                    "alert": "X-Frame-Options Header Not Set",
                    "name": "X-Frame-Options Header Not Set",
                    "riskcode": "2",
                    "confidence": "2",
                    "riskdesc": "Medium (Medium)",
                    "desc": "<p>X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.<\/p>",
                    "instances": [
                        {
                            "uri": "https://thisisanexample.com/sso?SAMLRequest=lZLex2Or%2BkFZY5mBWYvUzhaTk9VtEFnmvCC9k09XiK9Xw%3D%3D&RelayState=https%3A%2F%2Fthisisanexample.com%2F",
                            "method": "GET",
                            "param": "X-Frame-Options"
                        },
                        {
                            "uri": "https://thisisanexample.com/sso",
                            "method": "POST",
                            "param": "X-Frame-Options"
                        }
                    ],
                    "count": "2",
                    "solution": "<p>Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).<\/p>",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options<\/p>",
                    "cweid": "16",
                    "wascid": "15",
                    "sourceid": "3"
                }
            ]
        },
        {
            "@name": "https://thisithesecondexample.com",
            "@host": "thisithesecondexample.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {
                    "pluginid": "10021",
                    "alertRef": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "name": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "confidence": "2",
                    "riskdesc": "Low (Medium)",
                    "desc": "<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.<\/p>",
                    "instances": [
                        {
                            "uri": "https://thisithesecondexample.com",
                            "method": "GET",
                            "param": "X-Content-Type-Options"
                        }
                    ],
                    "count": "9",
                    "solution": "<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.<\/p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.<\/p>",
                    "otherinfo": "<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.<\/p><p>At \"High\" threshold this scan rule will not alert on client or server error responses.<\/p>",
                    "reference": "<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx<\/p><p>https://owasp.org/www-community/Security_Headers<\/p>",
                    "cweid": "16",
                    "wascid": "15",
                    "sourceid": "3"
                }
            ]
        }
    ]
}`
