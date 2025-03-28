package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/docker-trivy/types"
)

func TestParseCombinedOut(t *testing.T) {
	var results types.CombinedOut
	combinedOutput := fmt.Sprintf(`{"ubuntu:latest":%s,"alpine:latest":%s}`, exampleOutput, exampleOutput)
	err := json.Unmarshal([]byte(combinedOutput), &results)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
	issues := parseCombinedOut(results)

	expectedIssues := []*v1.Issue{{
		Target:     "pkg:apk/alpine/expat@2.2.6-r0",
		Type:       "Container image vulnerability",
		Title:      "[CVE-2020-27350] apt: integer overflows and underflows while parsing .deb packages",
		Severity:   v1.Severity_SEVERITY_MEDIUM,
		Cvss:       5.7,
		Confidence: v1.Confidence_CONFIDENCE_UNSPECIFIED,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\nOriginal Description:%s\n",
			"5.7", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L", "CVE-2020-27350",
			"CWE-190", "https://avd.aquasec.com/nvd/cve-2020-27350", "APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;"),
	}}

	found := 0
	assert.Equal(t, 2, len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Title == issue.Title {
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

func TestParseSingleOut(t *testing.T) {
	var results types.TrivyOut
	err := json.Unmarshal([]byte(exampleOutput), &results)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
	issues := parseSingleOut(results)

	expectedIssues := []*v1.Issue{{
		Target:     "pkg:apk/alpine/expat@2.2.6-r0",
		Type:       "Container image vulnerability",
		Title:      "[CVE-2020-27350] apt: integer overflows and underflows while parsing .deb packages",
		Severity:   v1.Severity_SEVERITY_MEDIUM,
		Cvss:       5.7,
		Confidence: v1.Confidence_CONFIDENCE_UNSPECIFIED,
		Description: fmt.Sprintf("CVSS Score: %v\nCvssVector: %s\nCve: %s\nCwe: %s\nReference: %s\nOriginal Description:%s\n",
			"5.7", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L", "CVE-2020-27350",
			"CWE-190", "https://avd.aquasec.com/nvd/cve-2020-27350", "APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;"),
	}}

	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Title == issue.Title {
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

func TestHandleSarif(t *testing.T) {
	results := trivySarif
	issues, err := handleSarif([]byte(results))
	require.NoError(t, err)
	expectedIssues := []*v1.Issue{
		{
			Target:     "library/ubuntu:1-1",
			Type:       "CVE-2016-2781",
			Title:      "Package: coreutils\nInstalled Version: 8.32-4.1ubuntu1\nVulnerability CVE-2016-2781\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)",
			Severity:   v1.Severity_SEVERITY_INFO,
			Confidence: v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Description: fmt.Sprintf("%v", `MatchedRule: {"id":"CVE-2016-2781","name":"OsPackageVulnerability","shortDescription":{"text":"coreutils: Non-privileged session can escape to the parent session in chroot"},"fullDescription":{"text":"chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2016-2781","help":{"text":"Vulnerability CVE-2016-2781\nSeverity: LOW\nPackage: coreutils\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.","markdown":"**Vulnerability CVE-2016-2781**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|coreutils||[CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)|\n\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}} 
 Message: Package: coreutils
Installed Version: 8.32-4.1ubuntu1
Vulnerability CVE-2016-2781
Severity: LOW
Fixed Version: 
Link: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)`),
		},
		{
			Target:     "library/ubuntu:1-1",
			Type:       "CVE-2022-3715",
			Severity:   v1.Severity_SEVERITY_INFO,
			Confidence: v1.Confidence_CONFIDENCE_UNSPECIFIED,
			Title:      "Package: bash\nInstalled Version: 5.1-6ubuntu1\nVulnerability CVE-2022-3715\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)",
			Description: fmt.Sprintf("%v", `MatchedRule: {"id":"CVE-2022-3715","name":"OsPackageVulnerability","shortDescription":{"text":"bash: a heap-buffer-overflow in valid_parameter_transform"},"fullDescription":{"text":"A flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-3715","help":{"text":"Vulnerability CVE-2022-3715\nSeverity: LOW\nPackage: bash\nFixed Version: \nLink: [CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)\nA flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems.","markdown":"**Vulnerability CVE-2022-3715**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|bash||[CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)|\n\nA flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}} 
 Message: Package: bash
Installed Version: 5.1-6ubuntu1
Vulnerability CVE-2022-3715
Severity: LOW
Fixed Version: 
Link: [CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)`),
		},
	}
	found := 0
	assert.Equal(t, len(expectedIssues), len(issues))
	for _, issue := range issues {
		singleMatch := 0
		for _, expected := range expectedIssues {
			if expected.Type == issue.Type {
				singleMatch++
				found++
				assert.Equal(t, singleMatch, 1) // assert no duplicates
				assert.EqualValues(t, expected.Type, issue.Type)
				assert.EqualValues(t, expected.Title, issue.Title)
				assert.EqualValues(t, expected.Severity, issue.Severity)
				assert.EqualValues(t, expected.Cvss, issue.Cvss)
				assert.EqualValues(t, expected.Confidence, issue.Confidence)
				assert.EqualValues(t, strings.TrimSpace(expected.Description), strings.TrimSpace(issue.Description))
			}
		}
	}
	assert.Equal(t, found, len(issues)) // assert everything has been found
}

const trivySarif = `{"version":"2.1.0","":"https://json.schemastore.org/sarif-2.1.0-rtm.5.json","runs":[{"tool":{"driver":{"fullName":"Trivy Vulnerability Scanner","informationUri":"https://github.com/aquasecurity/trivy","name":"Trivy","rules":[{"id":"CVE-2022-3715","name":"OsPackageVulnerability","shortDescription":{"text":"bash: a heap-buffer-overflow in valid_parameter_transform"},"fullDescription":{"text":"A flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-3715","help":{"text":"Vulnerability CVE-2022-3715\nSeverity: LOW\nPackage: bash\nFixed Version: \nLink: [CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)\nA flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems.","markdown":"**Vulnerability CVE-2022-3715**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|bash||[CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)|\n\nA flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2016-2781","name":"OsPackageVulnerability","shortDescription":{"text":"coreutils: Non-privileged session can escape to the parent session in chroot"},"fullDescription":{"text":"chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2016-2781","help":{"text":"Vulnerability CVE-2016-2781\nSeverity: LOW\nPackage: coreutils\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.","markdown":"**Vulnerability CVE-2016-2781**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|coreutils||[CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)|\n\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2022-3219","name":"OsPackageVulnerability","shortDescription":{"text":"gnupg: denial of service issue (resource consumption) using compressed packets"},"fullDescription":{"text":"No description is available for this CVE."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-3219","help":{"text":"Vulnerability CVE-2022-3219\nSeverity: LOW\nPackage: gpgv\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\nNo description is available for this CVE.","markdown":"**Vulnerability CVE-2022-3219**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|gpgv||[CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)|\n\nNo description is available for this CVE."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2016-20013","name":"OsPackageVulnerability","shortDescription":{"text":""},"fullDescription":{"text":"sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm&#39;s runtime is proportional to the square of the length of the password."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2016-20013","help":{"text":"Vulnerability CVE-2016-20013\nSeverity: LOW\nPackage: libc6\nFixed Version: \nLink: [CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)\nsha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.","markdown":"**Vulnerability CVE-2016-20013**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|libc6||[CVE-2016-20013](https://avd.aquasec.com/nvd/cve-2016-20013)|\n\nsha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2022-42898","name":"OsPackageVulnerability","shortDescription":{"text":"krb5: integer overflow vulnerabilities in PAC parsing"},"fullDescription":{"text":"PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has &#34;a similar bug.&#34;"},"defaultConfiguration":{"level":"warning"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-42898","help":{"text":"Vulnerability CVE-2022-42898\nSeverity: MEDIUM\nPackage: libkrb5support0\nFixed Version: \nLink: [CVE-2022-42898](https://avd.aquasec.com/nvd/cve-2022-42898)\nPAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has \"a similar bug.\"","markdown":"**Vulnerability CVE-2022-42898**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|MEDIUM|libkrb5support0||[CVE-2022-42898](https://avd.aquasec.com/nvd/cve-2022-42898)|\n\nPAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has \"a similar bug.\""},"properties":{"precision":"very-high","security-severity":"5.5","tags":["vulnerability","security","MEDIUM"]}},{"id":"CVE-2022-29458","name":"OsPackageVulnerability","shortDescription":{"text":"ncurses: segfaulting OOB read"},"fullDescription":{"text":"ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-29458","help":{"text":"Vulnerability CVE-2022-29458\nSeverity: LOW\nPackage: ncurses-bin\nFixed Version: \nLink: [CVE-2022-29458](https://avd.aquasec.com/nvd/cve-2022-29458)\nncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.","markdown":"**Vulnerability CVE-2022-29458**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|ncurses-bin||[CVE-2022-29458](https://avd.aquasec.com/nvd/cve-2022-29458)|\n\nncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2017-11164","name":"OsPackageVulnerability","shortDescription":{"text":"pcre: OP_KETRMAX feature in the match function in pcre_exec.c"},"fullDescription":{"text":"In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2017-11164","help":{"text":"Vulnerability CVE-2017-11164\nSeverity: LOW\nPackage: libpcre3\nFixed Version: \nLink: [CVE-2017-11164](https://avd.aquasec.com/nvd/cve-2017-11164)\nIn PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.","markdown":"**Vulnerability CVE-2017-11164**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|libpcre3||[CVE-2017-11164](https://avd.aquasec.com/nvd/cve-2017-11164)|\n\nIn PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2022-3996","name":"OsPackageVulnerability","shortDescription":{"text":"openssl: double locking leads to denial of service"},"fullDescription":{"text":"If an X.509 certificate contains a malformed policy constraint and policy processing is enabled, then a write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results in a denial of service when the affected process hangs. Policy processing being enabled on a publicly facing server is not considered to be a common setup. Policy processing is enabled by passing the '-policy&#39; argument to the command line utilities or by calling either 'X509_VERIFY_PARAM_add0_policy()&#39; or 'X509_VERIFY_PARAM_set1_policies()&#39; functions."},"defaultConfiguration":{"level":"note"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-3996","help":{"text":"Vulnerability CVE-2022-3996\nSeverity: LOW\nPackage: libssl3\nFixed Version: \nLink: [CVE-2022-3996](https://avd.aquasec.com/nvd/cve-2022-3996)\nIf an X.509 certificate contains a malformed policy constraint and policy processing is enabled, then a write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results in a denial of service when the affected process hangs. Policy processing being enabled on a publicly facing server is not considered to be a common setup. Policy processing is enabled by passing the '-policy' argument to the command line utilities or by calling either 'X509_VERIFY_PARAM_add0_policy()' or 'X509_VERIFY_PARAM_set1_policies()' functions.","markdown":"**Vulnerability CVE-2022-3996**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|LOW|libssl3||[CVE-2022-3996](https://avd.aquasec.com/nvd/cve-2022-3996)|\n\nIf an X.509 certificate contains a malformed policy constraint and policy processing is enabled, then a write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results in a denial of service when the affected process hangs. Policy processing being enabled on a publicly facing server is not considered to be a common setup. Policy processing is enabled by passing the '-policy' argument to the command line utilities or by calling either 'X509_VERIFY_PARAM_add0_policy()' or 'X509_VERIFY_PARAM_set1_policies()' functions."},"properties":{"precision":"very-high","security-severity":"2.0","tags":["vulnerability","security","LOW"]}},{"id":"CVE-2022-3821","name":"OsPackageVulnerability","shortDescription":{"text":"systemd: buffer overrun in format_timespan() function"},"fullDescription":{"text":"An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An attacker could supply specific values for time and accuracy that leads to buffer overrun in format_timespan(), leading to a Denial of Service."},"defaultConfiguration":{"level":"warning"},"helpUri":"https://avd.aquasec.com/nvd/cve-2022-3821","help":{"text":"Vulnerability CVE-2022-3821\nSeverity: MEDIUM\nPackage: libudev1\nFixed Version: \nLink: [CVE-2022-3821](https://avd.aquasec.com/nvd/cve-2022-3821)\nAn off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An attacker could supply specific values for time and accuracy that leads to buffer overrun in format_timespan(), leading to a Denial of Service.","markdown":"**Vulnerability CVE-2022-3821**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|MEDIUM|libudev1||[CVE-2022-3821](https://avd.aquasec.com/nvd/cve-2022-3821)|\n\nAn off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An attacker could supply specific values for time and accuracy that leads to buffer overrun in format_timespan(), leading to a Denial of Service."},"properties":{"precision":"very-high","security-severity":"5.5","tags":["vulnerability","security","MEDIUM"]}}],"version":"0.36.1"}},"results":[{"ruleId":"CVE-2022-3715","ruleIndex":0,"level":"note","message":{"text":"Package: bash\nInstalled Version: 5.1-6ubuntu1\nVulnerability CVE-2022-3715\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3715](https://avd.aquasec.com/nvd/cve-2022-3715)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"library/ubuntu","uriBaseId":"ROOTPATH"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":1}},"message":{"text":"library/ubuntu: bash@5.1-6ubuntu1"}}]},{"ruleId":"CVE-2016-2781","ruleIndex":1,"level":"note","message":{"text":"Package: coreutils\nInstalled Version: 8.32-4.1ubuntu1\nVulnerability CVE-2016-2781\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"library/ubuntu","uriBaseId":"ROOTPATH"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":1}},"message":{"text":"library/ubuntu: coreutils@8.32-4.1ubuntu1"}}]}],"columnKind":"utf16CodeUnits","originalUriBaseIds":{"ROOTPATH":{"uri":"file:///"}}}]}`

const exampleOutput = `{"Results":[{"Target":"ubuntu (ubuntu 18.04)","Type":"ubuntu","Vulnerabilities":[{"VulnerabilityID":"CVE-2020-27350","PkgName":"apt","PkgIdentifier":{"PURL":"pkg:apk/alpine/expat@2.2.6-r0","UID":"e24e675030cb5f4e"},"InstalledVersion":"1.6.12","FixedVersion":"1.6.12ubuntu0.2","Layer":{"DiffID":"sha256:a090697502b8d19fbc83afb24d8fb59b01e48bf87763a00ca55cfff42423ad36"},"SeveritySource":"ubuntu","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2020-27350","Title":"apt: integer overflows and underflows while parsing .deb packages","Description":"APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;","Severity":"MEDIUM","CweIDs":["CWE-190"],"CVSS":{"nvd":{"V2Vector":"AV:L/AC:L/Au:N/C:P/I:P/A:P","V3Vector":"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L","V2Score":4.6,"V3Score":5.7},"redhat":{"V3Vector":"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L","V3Score":5.7}},"References":["https://bugs.launchpad.net/bugs/1899193","https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350","https://security.netapp.com/advisory/ntap-20210108-0005/","https://usn.ubuntu.com/usn/usn-4667-1","https://usn.ubuntu.com/usn/usn-4667-2","https://www.debian.org/security/2020/dsa-4808"],"PublishedDate":"2020-12-10T04:15:00Z","LastModifiedDate":"2021-01-08T12:15:00Z"}]}]}`

func TestEndToEndCLIWithJSON(t *testing.T) {
	err := producers.TestEndToEnd(t, "./examples/trivy_python-3-4-alpine.json", "./examples/trivy_python-3-4-alpine.pb")
	assert.NoError(t, err)
}
