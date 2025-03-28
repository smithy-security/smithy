package main

import (
	"encoding/json"
	"testing"

	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/python-pip-safety/types"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIssues(t *testing.T) {
	safetyIssues := types.Out{}
	err := json.Unmarshal([]byte(exampleOutput), &safetyIssues)
	require.NoError(t, err)
	smithyIssues := parseIssues(safetyIssues.Vulnerabilities)
	expectedIssues := []*v1.Issue{
		{
			Target:      "pkg:pypi/aiohttp-jinja2@1.1.0",
			Type:        "Vulnerable Dependency",
			Title:       "aiohttp-jinja2[<1.1.1]",
			Severity:    0,
			Cvss:        0,
			Confidence:  3,
			Description: "Advisory: Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.\nFixed Versions: [],Resources: [], More Info: https://pyup.io/vulnerabilities/CVE-2014-1402/37095/",
			Source:      "",
			Cve:         "CVE-2014-1402",
		},
		{
			Target:      "pkg:pypi/aiohttp-jinja2@1.1.0",
			Type:        "Vulnerable Dependency",
			Title:       "aiohttp-jinja2[<1.1.1]",
			Severity:    0,
			Cvss:        0,
			Confidence:  3,
			Description: "Advisory: Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.\nFixed Versions: [],Resources: [], More Info: https://pyup.io/vulnerabilities/CVE-2016-10745/44431/",
			Source:      "",
			Cve:         "CVE-2016-10745",
		},
		{
			Target:      "pkg:pypi/aiohttp-jinja2@1.1.0",
			Type:        "Vulnerable Dependency",
			Title:       "aiohttp-jinja2[<1.1.1]",
			Severity:    0,
			Cvss:        0,
			Confidence:  3,
			Description: "Advisory: Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.\nFixed Versions: [],Resources: [], More Info: https://pyup.io/vulnerabilities/CVE-2019-10906/44432/",
			Source:      "",
			Cve:         "CVE-2019-10906",
		},
	}

	assert.Equal(t, smithyIssues, expectedIssues)
}

const exampleOutput = `
{
    "report_meta": {
        "scan_target": "files",
        "scanned": [
            "requirements.txt"
        ],
        "policy_file": null,
        "policy_file_source": "local",
        "api_key": false,
        "local_database_path": null,
        "safety_version": "2.1.1",
        "timestamp": "2022-08-08 15:54:08",
        "packages_found": 18,
        "vulnerabilities_found": 9,
        "vulnerabilities_ignored": 0,
        "remediations_recommended": 0,
        "telemetry": {
            "os_type": "Linux",
            "os_release": "5.15.0-43-generic",
            "os_description": "Linux-5.15.0-43-generic-x86_64-with-glibc2.31",
            "python_version": "3.10.6",
            "safety_command": "check",
            "safety_options": {
                "files": {
                    "-r": 1
                },
                "save_json": {
                    "--save-json": 1
                }
            },
            "safety_version": "2.1.1",
            "safety_source": "cli"
        },
        "git": {
            "branch": "master",
            "tag": "",
            "commit": "b11d0415f86cc2285158d2f07c81cd9777d8fffb",
            "dirty": false,
            "origin": "https://github.com/anxolerd/dvpwa"
        },
        "project": null,
        "json_version": 1
    },
    "scanned_packages": {
        "aiohttp-jinja2": {
            "name": "aiohttp-jinja2",
            "version": "1.1.0"
        },
        "aiohttp-session": {
            "name": "aiohttp-session",
            "version": "2.7.0"
        },
        "aiohttp": {
            "name": "aiohttp",
            "version": "3.5.3"
        },
        "aiopg": {
            "name": "aiopg",
            "version": "0.15.0"
        },
        "aioredis": {
            "name": "aioredis",
            "version": "1.2.0"
        },
        "async-timeout": {
            "name": "async-timeout",
            "version": "3.0.1"
        },
        "attrs": {
            "name": "attrs",
            "version": "18.2.0"
        },
        "chardet": {
            "name": "chardet",
            "version": "3.0.4"
        },
        "hiredis": {
            "name": "hiredis",
            "version": "0.3.1"
        },
        "idna": {
            "name": "idna",
            "version": "2.8"
        },
        "jinja2": {
            "name": "jinja2",
            "version": "2.10"
        },
        "markupsafe": {
            "name": "markupsafe",
            "version": "1.1.0"
        },
        "multidict": {
            "name": "multidict",
            "version": "4.5.2"
        },
        "psycopg2": {
            "name": "psycopg2",
            "version": "2.7.6.1"
        },
        "pyyaml": {
            "name": "pyyaml",
            "version": "3.13"
        },
        "trafaret-config": {
            "name": "trafaret-config",
            "version": "2.0.2"
        },
        "trafaret": {
            "name": "trafaret",
            "version": "1.2.0"
        },
        "yarl": {
            "name": "yarl",
            "version": "1.3.0"
        }
    },
    "affected_packages": {
        "aiohttp-jinja2": {
            "name": "aiohttp-jinja2",
            "version": "1.1.0",
            "found": "requirements.txt",
            "insecure_versions": [],
            "secure_versions": [],
            "latest_version_without_known_vulnerabilities": null,
            "latest_version": null,
            "more_info_url": "https://pyup.io"
        },
        "aiohttp": {
            "name": "aiohttp",
            "version": "3.5.3",
            "found": "requirements.txt",
            "insecure_versions": [],
            "secure_versions": [],
            "latest_version_without_known_vulnerabilities": null,
            "latest_version": null,
            "more_info_url": "https://pyup.io"
        },
        "jinja2": {
            "name": "jinja2",
            "version": "2.10",
            "found": "requirements.txt",
            "insecure_versions": [],
            "secure_versions": [],
            "latest_version_without_known_vulnerabilities": null,
            "latest_version": null,
            "more_info_url": "https://pyup.io"
        },
        "pyyaml": {
            "name": "pyyaml",
            "version": "3.13",
            "found": "requirements.txt",
            "insecure_versions": [],
            "secure_versions": [],
            "latest_version_without_known_vulnerabilities": null,
            "latest_version": null,
            "more_info_url": "https://pyup.io"
        }
    },
    "announcements": [],
    "vulnerabilities": [
        {
            "vulnerability_id": "37095",
            "package_name": "aiohttp-jinja2",
            "ignored": {},
            "ignored_reason": null,
            "ignored_expires": null,
            "vulnerable_spec": ["<1.1.1"],
            "all_vulnerable_specs": [
                "<1.1.1"
            ],
            "analyzed_version": "1.1.0",
            "advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
            "is_transitive": false,
            "published_date": null,
            "fixed_versions": [],
            "closest_versions_without_known_vulnerabilities": [],
            "resources": [],
            "CVE": "CVE-2014-1402",
            "severity": null,
            "affected_versions": [],
            "more_info_url": "https://pyup.io/vulnerabilities/CVE-2014-1402/37095/"
        },
        {
            "vulnerability_id": "44431",
            "package_name": "aiohttp-jinja2",
            "ignored": {},
            "ignored_reason": null,
            "ignored_expires": null,
            "vulnerable_spec": ["<1.1.1"],
            "all_vulnerable_specs": [
                "<1.1.1"
            ],
            "analyzed_version": "1.1.0",
            "advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
            "is_transitive": false,
            "published_date": null,
            "fixed_versions": [],
            "closest_versions_without_known_vulnerabilities": [],
            "resources": [],
            "CVE": "CVE-2016-10745",
            "severity": null,
            "affected_versions": [],
            "more_info_url": "https://pyup.io/vulnerabilities/CVE-2016-10745/44431/"
        },
        {
            "vulnerability_id": "44432",
            "package_name": "aiohttp-jinja2",
            "ignored": {},
            "ignored_reason": null,
            "ignored_expires": null,
            "vulnerable_spec": ["<1.1.1"],
            "all_vulnerable_specs": [
                "<1.1.1"
            ],
            "analyzed_version": "1.1.0",
            "advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
            "is_transitive": false,
            "published_date": null,
            "fixed_versions": [],
            "closest_versions_without_known_vulnerabilities": [],
            "resources": [],
            "CVE": "CVE-2019-10906",
            "severity": null,
            "affected_versions": [],
            "more_info_url": "https://pyup.io/vulnerabilities/CVE-2019-10906/44432/"
        }
    ],
    "ignored_vulnerabilities": [],
    "remediations": {
        "aiohttp-jinja2": {
            "current_version": "1.1.0",
            "vulnerabilities_found": 3,
            "recommended_version": null,
            "other_recommended_versions": [],
            "more_info_url": "https://pyup.io"
        },
        "aiohttp": {
            "current_version": "3.5.3",
            "vulnerabilities_found": 2,
            "recommended_version": null,
            "other_recommended_versions": [],
            "more_info_url": "https://pyup.io"
        }
    }
}`

func TestEndToEndCLIWithJSON(t *testing.T) {
	err := producers.TestEndToEnd(t, "./examples/result.json", "./examples/result_safety.pb")
	assert.NoError(t, err)
}
