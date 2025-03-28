package main

import (
	"encoding/json"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/assert"
)

func TestParseIssues(t *testing.T) {
	var results DependencyTrackOut
	err := json.Unmarshal([]byte(dtOut), &results)
	assert.Nil(t, err)

	issues, err := parseIssues(&results)
	assert.Nil(t, err)
	cwe0 := []int32{400}
	cwe1 := []int32{601, 918}
	expectedIssue := []*v1.Issue{
		{
			Target:   "pkg:maven/org.springframework/spring-core@6.1.2",
			Type:     "SNYK-JAVA-ORGSPRINGFRAMEWORK-6183818",
			Title:    "Uncontrolled Resource Consumption ('Resource Exhaustion')",
			Severity: 4, Cvss: 7.5, Confidence: 0,
			Description: "## Overview\n[org.springframework:spring-core](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22spring-core%22) is a core package within the spring-framework that contains multiple classes and utilities.\n\nAffected versions of this package are vulnerable to Uncontrolled Resource Consumption ('Resource Exhaustion') via specially crafted HTTP requests. An attacker can cause a denial-of-service condition by sending malicious requests that exploit this issue. \r\n\r\n**Notes:**\r\n\r\nThis is only exploitable if the application uses Spring MVC and Spring Security 6.1.6+ or 6.2.1+ is on the classpath.\r\n\r\nTypically, Spring Boot applications need the 'org.springframework.boot:spring-boot-starter-web' and 'org.springframework.boot:spring-boot-starter-security' dependencies to meet all conditions.\n## Remediation\nUpgrade 'org.springframework:spring-core' to version 6.0.16, 6.1.3 or higher.\n## References\n- [Vulnerability Advisory](https://spring.io/security/cve-2024-22233/)\n\nUpgrade the package version to 6.0.16,6.1.3 to fix this vulnerability\nVulnerability Aliases:\n{\"cveId\":\"CVE-2024-22233\",\"snykId\":\"SNYK-JAVA-ORGSPRINGFRAMEWORK-6183818\"}",
			Source:      "", Cve: "CVE-2024-22233", Uuid: "",
			Cwe: cwe0,
		},
		{
			Target:   "pkg:maven/org.springframework/spring-web@6.1.2",
			Type:     "SNYK-JAVA-ORGSPRINGFRAMEWORK-6261586",
			Title:    "Open Redirect",
			Severity: 4, Cvss: 7.1, Confidence: 0,
			Description: "## Overview\n[org.springframework:spring-web](https://github.com/spring-projects/spring-framework) is a package that provides a comprehensive programming and configuration model for modern Java-based enterprise applications - on any kind of deployment platform.\n\nAffected versions of this package are vulnerable to Open Redirect when 'UriComponentsBuilder' parses an externally provided URL, and the application subsequently uses that URL. If it contains hierarchical components such as path, query, and fragment it may evade validation.\n## Remediation\nUpgrade 'org.springframework:spring-web' to version 5.3.32, 6.0.17, 6.1.4 or higher.\n## References\n- [GitHub Commit](https://github.com/spring-projects/spring-framework/commit/120ea0a51c63171e624ca55dbd7cae627d53a042)\n- [Spring Advisory](https://spring.io/security/cve-2024-22243)\n\nUpgrade the package version to 5.3.32,6.0.17,6.1.4 to fix this vulnerability\nVulnerability Aliases:\n{\"cveId\":\"CVE-2024-22243\",\"snykId\":\"SNYK-JAVA-ORGSPRINGFRAMEWORK-6261586\"}",
			Source:      "",
			Cve:         "CVE-2024-22243",
			Uuid:        "",
			Cwe:         cwe1,
		},
	}
	assert.Equal(t, expectedIssue, issues)
}

const dtOut = `[
    {
        "component": {
            "uuid": "51c94900-b724-490c-96ef-044f818b84ac",
            "name": "org.springframework:spring-core",
            "group": "org.springframework",
            "version": "6.1.2",
            "purl": "pkg:maven/org.springframework/spring-core@6.1.2",
            "project": "11615114-cfbb-422d-9816-7f5f37380f53",
            "latestVersion": "6.1.4"
        },
        "vulnerability": {
            "uuid": "1fdfb487-1ff8-4ebb-8393-37a64b7b8958",
            "source": "SNYK",
            "vulnId": "SNYK-JAVA-ORGSPRINGFRAMEWORK-6183818",
            "title": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
            "cvssV3BaseScore": 7.5,
            "severity": "HIGH",
            "severityRank": 1,
            "cweId": 400,
            "cweName": "Uncontrolled Resource Consumption",
            "cwes": [
                {
                    "cweId": 400,
                    "name": "Uncontrolled Resource Consumption"
                }
            ],
            "aliases": [
                {
                    "cveId": "CVE-2024-22233",
                    "snykId": "SNYK-JAVA-ORGSPRINGFRAMEWORK-6183818"
                }
            ],
            "description": "## Overview\n[org.springframework:spring-core](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22spring-core%22) is a core package within the spring-framework that contains multiple classes and utilities.\n\nAffected versions of this package are vulnerable to Uncontrolled Resource Consumption ('Resource Exhaustion') via specially crafted HTTP requests. An attacker can cause a denial-of-service condition by sending malicious requests that exploit this issue. \r\n\r\n**Notes:**\r\n\r\nThis is only exploitable if the application uses Spring MVC and Spring Security 6.1.6+ or 6.2.1+ is on the classpath.\r\n\r\nTypically, Spring Boot applications need the 'org.springframework.boot:spring-boot-starter-web' and 'org.springframework.boot:spring-boot-starter-security' dependencies to meet all conditions.\n## Remediation\nUpgrade 'org.springframework:spring-core' to version 6.0.16, 6.1.3 or higher.\n## References\n- [Vulnerability Advisory](https://spring.io/security/cve-2024-22233/)\n",
            "recommendation": "Upgrade the package version to 6.0.16,6.1.3 to fix this vulnerability"
        },
        "analysis": {
            "isSuppressed": false
        },
        "attribution": {
            "analyzerIdentity": "SNYK_ANALYZER",
            "attributedOn": 1708948806826
        },
        "matrix": "11615114-cfbb-422d-9816-7f5f37380f53:51c94900-b724-490c-96ef-044f818b84ac:1fdfb487-1ff8-4ebb-8393-37a64b7b8958"
    },
    {
        "component": {
            "uuid": "995089ce-38ee-4e51-9be8-77e6567426aa",
            "name": "org.springframework:spring-web",
            "group": "org.springframework",
            "version": "6.1.2",
            "purl": "pkg:maven/org.springframework/spring-web@6.1.2",
            "project": "11615114-cfbb-422d-9816-7f5f37380f53",
            "latestVersion": "6.1.4"
        },
        "vulnerability": {
            "uuid": "fe774955-fda4-44e7-b7a8-f51fc22aa540",
            "source": "SNYK",
            "vulnId": "SNYK-JAVA-ORGSPRINGFRAMEWORK-6261586",
            "title": "Open Redirect",
            "cvssV3BaseScore": 7.1,
            "severity": "HIGH",
            "severityRank": 1,
            "cweId": 601,
            "cweName": "URL Redirection to Untrusted Site ('Open Redirect')",
            "cwes": [
                {
                    "cweId": 601,
                    "name": "URL Redirection to Untrusted Site ('Open Redirect')"
                },
                {
                    "cweId": 918,
                    "name": "Server-Side Request Forgery (SSRF)"
                }
            ],
            "aliases": [
                {
                    "cveId": "CVE-2024-22243",
                    "snykId": "SNYK-JAVA-ORGSPRINGFRAMEWORK-6261586"
                }
            ],
            "description": "## Overview\n[org.springframework:spring-web](https://github.com/spring-projects/spring-framework) is a package that provides a comprehensive programming and configuration model for modern Java-based enterprise applications - on any kind of deployment platform.\n\nAffected versions of this package are vulnerable to Open Redirect when 'UriComponentsBuilder' parses an externally provided URL, and the application subsequently uses that URL. If it contains hierarchical components such as path, query, and fragment it may evade validation.\n## Remediation\nUpgrade 'org.springframework:spring-web' to version 5.3.32, 6.0.17, 6.1.4 or higher.\n## References\n- [GitHub Commit](https://github.com/spring-projects/spring-framework/commit/120ea0a51c63171e624ca55dbd7cae627d53a042)\n- [Spring Advisory](https://spring.io/security/cve-2024-22243)\n",
            "recommendation": "Upgrade the package version to 5.3.32,6.0.17,6.1.4 to fix this vulnerability"
        },
        "analysis": {
            "isSuppressed": false
        },
        "attribution": {
            "analyzerIdentity": "SNYK_ANALYZER",
            "attributedOn": 1708948807077
        },
        "matrix": "11615114-cfbb-422d-9816-7f5f37380f53:995089ce-38ee-4e51-9be8-77e6567426aa:fe774955-fda4-44e7-b7a8-f51fc22aa540"
    }
]`
