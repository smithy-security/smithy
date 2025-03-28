package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalJSON(t *testing.T) {
	expectedOutput := Out{Vulnerabilities: []Vulnerability{
		{
			PackageName:        "aiohttp-jinja2",
			VulnerableSpec:     []string{"<1.1.1"},
			AllVulnerableSpecs: []string{"<1.1.1"},
			AnalyzedVersion:    "1.1.0",
			Advisory:           "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			PublishedDate:      "",
			FixedVersions:      []string{},
			Resources:          []string{},
			CVE:                "CVE-2014-1402",
			Severity:           "",
			AffectedVersions:   []string{},
			MoreInfoURL:        "https://pyup.io/vulnerabilities/CVE-2014-1402/37095/",
		},
		{
			PackageName:        "aiohttp-jinja2",
			VulnerableSpec:     []string{"<1.1.1"},
			AllVulnerableSpecs: []string{"<1.1.1"},
			AnalyzedVersion:    "1.1.0",
			Advisory:           "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			PublishedDate:      "",
			FixedVersions:      []string{},
			Resources:          []string{},
			CVE:                "CVE-2016-10745",
			Severity:           "",
			AffectedVersions:   []string{},
			MoreInfoURL:        "https://pyup.io/vulnerabilities/CVE-2016-10745/44431/",
		},
		{
			PackageName:        "aiohttp-jinja2",
			VulnerableSpec:     []string{"<1.1.1"},
			AllVulnerableSpecs: []string{"<1.1.1"},
			AnalyzedVersion:    "1.1.0",
			Advisory:           "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			PublishedDate:      "",
			FixedVersions:      []string{},
			Resources:          []string{},
			CVE:                "CVE-2019-10906",
			Severity:           "",
			AffectedVersions:   []string{},
			MoreInfoURL:        "https://pyup.io/vulnerabilities/CVE-2019-10906/44432/",
		},
		{
			PackageName:        "aiohttp",
			VulnerableSpec:     []string{"<3.7.4"},
			AllVulnerableSpecs: []string{"<3.7.4"},
			AnalyzedVersion:    "3.5.3",
			Advisory:           "Aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. In aiohttp before version 3.7.4 there is an open redirect vulnerability. A maliciously crafted link to an aiohttp-based web-server could redirect the browser to a different website. It is caused by a bug in the 'aiohttp.web_middlewares.normalize_path_middleware' middleware. This security problem has been fixed in 3.7.4. Upgrade your dependency using pip as follows \"pip install aiohttp >= 3.7.4\". If upgrading is not an option for you, a workaround can be to avoid using 'aiohttp.web_middlewares.normalize_path_middleware' in your applications. See CVE-2021-21330.",
			PublishedDate:      "",
			FixedVersions:      []string{},
			Resources:          []string{},
			CVE:                "CVE-2021-21330",
			Severity:           "",
			AffectedVersions:   []string{},
			MoreInfoURL:        "https://pyup.io/vulnerabilities/CVE-2021-21330/39659/",
		},
		{
			PackageName:        "aiohttp",
			VulnerableSpec:     []string{"<3.8.0"},
			AllVulnerableSpecs: []string{"<3.8.0"},
			AnalyzedVersion:    "3.5.3",
			Advisory:           "Aiohttp 3.8.0 adds validation of HTTP header keys and values to prevent header injection.\r\nhttps://github.com/aio-libs/aiohttp/issues/4818",
			PublishedDate:      "",
			FixedVersions:      []string{},
			Resources:          []string{},
			CVE:                "",
			Severity:           "",
			AffectedVersions:   []string{},
			MoreInfoURL:        "https://pyup.io/vulnerabilities/PVE-2021-42692/42692/",
		},
	}}

	safetyIssues := Out{}
	err := json.Unmarshal([]byte(exampleOutput), &safetyIssues)
	require.NoError(t, err)
	assert.Equal(t, safetyIssues, expectedOutput)
}

const exampleOutput = `
{
	"report_meta": {
		"scan_target": "files",
		"scanned": [
			"requirements.txt"
		],
		"policy_file": "",
		"policy_file_source": "local",
		"api_key": false,
		"local_database_path": "",
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
		"project": "",
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
			"latest_version_without_known_vulnerabilities": "",
			"latest_version": "",
			"more_info_url": "https://pyup.io"
		},
		"aiohttp": {
			"name": "aiohttp",
			"version": "3.5.3",
			"found": "requirements.txt",
			"insecure_versions": [],
			"secure_versions": [],
			"latest_version_without_known_vulnerabilities": "",
			"latest_version": "",
			"more_info_url": "https://pyup.io"
		},
		"jinja2": {
			"name": "jinja2",
			"version": "2.10",
			"found": "requirements.txt",
			"insecure_versions": [],
			"secure_versions": [],
			"latest_version_without_known_vulnerabilities": "",
			"latest_version": "",
			"more_info_url": "https://pyup.io",
			"MoreInfoURL": "https://pyup.io"
		},
		"pyyaml": {
			"name": "pyyaml",
			"version": "3.13",
			"found": "requirements.txt",
			"insecure_versions": [],
			"secure_versions": [],
			"latest_version_without_known_vulnerabilities": "",
			"latest_version": "",
			"more_info_url": "https://pyup.io"
		}
	},
	"announcements": [],
	"vulnerabilities": [{
			"vulnerability_id": "37095",
			"package_name": "aiohttp-jinja2",
			"ignored": {},
			"ignored_reason": "",
			"ignored_expires": "",
			"vulnerable_spec": ["<1.1.1"],
			"all_vulnerable_specs": [
				"<1.1.1"
			],
			"analyzed_version": "1.1.0",
			"advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			"is_transitive": false,
			"published_date": "",
			"fixed_versions": [],
			"closest_versions_without_known_vulnerabilities": [],
			"resources": [],
			"cve": "CVE-2014-1402",
			"severity": "",
			"affected_versions": [],
			"more_info_url": "https://pyup.io/vulnerabilities/CVE-2014-1402/37095/"
		},
		{
			"vulnerability_id": "44431",
			"package_name": "aiohttp-jinja2",
			"ignored": {},
			"ignored_reason": "",
			"ignored_expires": "",
			"vulnerable_spec": ["<1.1.1"],
			"all_vulnerable_specs": [
				"<1.1.1"
			],
			"analyzed_version": "1.1.0",
			"advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			"is_transitive": false,
			"published_date": "",
			"fixed_versions": [],
			"closest_versions_without_known_vulnerabilities": [],
			"resources": [],
			"cve": "CVE-2016-10745",
			"severity": "",
			"affected_versions": [],
			"more_info_url": "https://pyup.io/vulnerabilities/CVE-2016-10745/44431/"
		},
		{
			"vulnerability_id": "44432",
			"package_name": "aiohttp-jinja2",
			"ignored": {},
			"ignored_reason": "",
			"ignored_expires": "",
			"vulnerable_spec": ["<1.1.1"],
			"all_vulnerable_specs": [
				"<1.1.1"
			],
			"analyzed_version": "1.1.0",
			"advisory": "Aiohttp-jinja2 1.1.1 updates minimal supported 'Jinja2' version to 2.10.1 to include security fixes.",
			"is_transitive": false,
			"published_date": "",
			"fixed_versions": [],
			"closest_versions_without_known_vulnerabilities": [],
			"resources": [],
			"cve": "CVE-2019-10906",
			"severity": "",
			"affected_versions": [],
			"more_info_url": "https://pyup.io/vulnerabilities/CVE-2019-10906/44432/"
		},
		{
			"vulnerability_id": "39659",
			"package_name": "aiohttp",
			"ignored": {},
			"ignored_reason": "",
			"ignored_expires": "",
			"vulnerable_spec": ["<3.7.4"],
			"all_vulnerable_specs": [
				"<3.7.4"
			],
			"analyzed_version": "3.5.3",
			"advisory": "Aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. In aiohttp before version 3.7.4 there is an open redirect vulnerability. A maliciously crafted link to an aiohttp-based web-server could redirect the browser to a different website. It is caused by a bug in the 'aiohttp.web_middlewares.normalize_path_middleware' middleware. This security problem has been fixed in 3.7.4. Upgrade your dependency using pip as follows \"pip install aiohttp >= 3.7.4\". If upgrading is not an option for you, a workaround can be to avoid using 'aiohttp.web_middlewares.normalize_path_middleware' in your applications. See CVE-2021-21330.",
			"is_transitive": false,
			"published_date": "",
			"fixed_versions": [],
			"closest_versions_without_known_vulnerabilities": [],
			"resources": [],
			"cve": "CVE-2021-21330",
			"severity": "",
			"affected_versions": [],
			"more_info_url": "https://pyup.io/vulnerabilities/CVE-2021-21330/39659/"
		},
		{
			"vulnerability_id": "42692",
			"package_name": "aiohttp",
			"ignored": {},
			"ignored_reason": "",
			"ignored_expires": "",
			"vulnerable_spec": ["<3.8.0"],
			"all_vulnerable_specs": [
				"<3.8.0"
			],
			"analyzed_version": "3.5.3",
			"advisory": "Aiohttp 3.8.0 adds validation of HTTP header keys and values to prevent header injection.\r\nhttps://github.com/aio-libs/aiohttp/issues/4818",
			"is_transitive": false,
			"published_date": "",
			"fixed_versions": [],
			"closest_versions_without_known_vulnerabilities": [],
			"resources": [],
			"cve": "",
			"severity": "",
			"affected_versions": [],
			"more_info_url": "https://pyup.io/vulnerabilities/PVE-2021-42692/42692/"
		}
	],
	"ignored_vulnerabilities": [],
	"remediations": {
		"aiohttp-jinja2": {
			"current_version": "1.1.0",
			"vulnerabilities_found": 3,
			"recommended_version": "",
			"other_recommended_versions": [],
			"more_info_url": "https://pyup.io"
		},
		"aiohttp": {
			"current_version": "3.5.3",
			"vulnerabilities_found": 2,
			"recommended_version": "",
			"other_recommended_versions": [],
			"more_info_url": "https://pyup.io"
		}
	}
}`
