package javascript

import (
	"github.com/smithy-security/pkg/utils"
	ocsfv1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

var Results = []*ocsfv1.VulnerabilityFinding{
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2018-1002204",
			Title:       "Arbitrary File Write in adm-zip",
			Desc:        utils.Ptr("Versions of `adm-zip` before 0.4.9 are vulnerable to arbitrary file write when used to extract a specifically crafted archive that contains path traversal filenames (`../../file.txt` for example).\n\n\n## Recommendation\n\nUpdate to version 0.4.9 or later."),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":158, "endLine":158}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Arbitrary File Write in adm-zip"),
				Desc:  utils.Ptr("Versions of `adm-zip` before 0.4.9 are vulnerable to arbitrary file write when used to extract a specifically crafted archive that contains path traversal filenames (`../../file.txt` for example).\n\n\n## Recommendation\n\nUpdate to version 0.4.9 or later."),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2018-1002204"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "adm-zip", Version: "0.4.4"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(158)),
						EndLine:   utils.Ptr(int32(158)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2020-15366",
			Title:       "Prototype Pollution in Ajv",
			Desc:        utils.Ptr("An issue was discovered in ajv.validate() in Ajv (aka Another JSON Schema Validator) 6.12.2. A carefully crafted JSON schema could be provided that allows execution of other code by prototype pollution. (While untrusted schemas are recommended against, the worst case of an untrusted schema should be a denial of service, not execution of code.)"),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":167, "endLine":167}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Prototype Pollution in Ajv"),
				Desc:  utils.Ptr("An issue was discovered in ajv.validate() in Ajv (aka Another JSON Schema Validator) 6.12.2. A carefully crafted JSON schema could be provided that allows execution of other code by prototype pollution. (While untrusted schemas are recommended against, the worst case of an untrusted schema should be a denial of service, not execution of code.)"),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2020-15366"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "ajv", Version: "6.10.0"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(167)),
						EndLine:   utils.Ptr(int32(167)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2021-3807",
			Title:       "Inefficient Regular Expression Complexity in chalk/ansi-regex",
			Desc:        utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":196, "endLine":196}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Inefficient Regular Expression Complexity in chalk/ansi-regex"),
				Desc:  utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2021-3807"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "ansi-regex", Version: "3.0.0"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(196)),
						EndLine:   utils.Ptr(int32(196)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2021-3807",
			Title:       "Inefficient Regular Expression Complexity in chalk/ansi-regex",
			Desc:        utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":714, "endLine":714}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Inefficient Regular Expression Complexity in chalk/ansi-regex"),
				Desc:  utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2021-3807"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "ansi-regex", Version: "3.0.0"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(714)),
						EndLine:   utils.Ptr(int32(714)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2021-3807",
			Title:       "Inefficient Regular Expression Complexity in chalk/ansi-regex",
			Desc:        utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":14909, "endLine":14909}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Inefficient Regular Expression Complexity in chalk/ansi-regex"),
				Desc:  utils.Ptr("ansi-regex is vulnerable to Inefficient Regular Expression Complexity which could lead to a denial of service when parsing invalid ANSI escape codes.\n\n**Proof of Concept**\n```js\nimport ansiRegex from 'ansi-regex';\nfor(var i = 1; i <= 50000; i++) {\n    var time = Date.now();\n    var attack_str = \"\\u001B[\"+\";\".repeat(i*10000);\n    ansiRegex().test(attack_str)\n    var time_cost = Date.now() - time;\n    console.log(\"attack_str.length: \" + attack_str.length + \": \" + time_cost+\" ms\")\n}\n```\nThe ReDOS is mainly due to the sub-patterns `[[\\\\]()#;?]*` and `(?:;[-a-zA-Z\\\\d\\\\/#&.:=?%@~_]*)*`"),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2021-3807"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "ansi-regex", Version: "3.0.0"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(14909)),
						EndLine:   utils.Ptr(int32(14909)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2021-43138",
			Title:       "Prototype Pollution in async",
			Desc:        utils.Ptr("A vulnerability exists in Async through 3.2.1 for 3.x and through 2.6.3 for 2.x (fixed in 3.2.2 and 2.6.4), which could let a malicious user obtain privileges via the `mapValues()` method."),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":419, "endLine":419}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Prototype Pollution in async"),
				Desc:  utils.Ptr("A vulnerability exists in Async through 3.2.1 for 3.x and through 2.6.3 for 2.x (fixed in 3.2.2 and 2.6.4), which could let a malicious user obtain privileges via the `mapValues()` method."),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2021-43138"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "async", Version: "2.6.1"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(419)),
						EndLine:   utils.Ptr(int32(419)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2021-43138",
			Title:       "Prototype Pollution in async",
			Desc:        utils.Ptr("A vulnerability exists in Async through 3.2.1 for 3.x and through 2.6.3 for 2.x (fixed in 3.2.2 and 2.6.4), which could let a malicious user obtain privileges via the `mapValues()` method."),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":4663, "endLine":4663}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Prototype Pollution in async"),
				Desc:  utils.Ptr("A vulnerability exists in Async through 3.2.1 for 3.x and through 2.6.3 for 2.x (fixed in 3.2.2 and 2.6.4), which could let a malicious user obtain privileges via the `mapValues()` method."),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2021-43138"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "async", Version: "2.6.1"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(4663)),
						EndLine:   utils.Ptr(int32(4663)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2023-45133",
			Title:       "Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code",
			Desc:        utils.Ptr("### Impact\n\nUsing Babel to compile code that was specifically crafted by an attacker can lead to arbitrary code execution during compilation, when using plugins that rely on the `path.evaluate()`or `path.evaluateTruthy()` internal Babel methods.\n\nKnown affected plugins are:\n- `@babel/plugin-transform-runtime`\n- `@babel/preset-env` when using its [`useBuiltIns`](https://babeljs.io/docs/babel-preset-env#usebuiltins) option\n- Any \"polyfill provider\" plugin that depends on `@babel/helper-define-polyfill-provider`, such as `babel-plugin-polyfill-corejs3`, `babel-plugin-polyfill-corejs2`, `babel-plugin-polyfill-es-shims`, `babel-plugin-polyfill-regenerator`\n\nNo other plugins under the `@babel/` namespace are impacted, but third-party plugins might be.\n\n**Users that only compile trusted code are not impacted.**\n\n### Patches\n\nThe vulnerability has been fixed in `@babel/traverse@7.23.2`.\n\nBabel 6 does not receive security fixes anymore (see [Babel's security policy](https://github.com/babel/babel/security/policy)), hence there is no patch planned for `babel-traverse@6`.\n\n### Workarounds\n\n- Upgrade `@babel/traverse` to v7.23.2 or higher. You can do this by deleting it from your package manager's lockfile and re-installing the dependencies. `@babel/core` \u003e=7.23.2 will automatically pull in a non-vulnerable version.\n- If you cannot upgrade `@babel/traverse` and are using one of the affected packages mentioned above, upgrade them to their latest version to avoid triggering the vulnerable code path in affected `@babel/traverse` versions:\n  - `@babel/plugin-transform-runtime` v7.23.2\n  - `@babel/preset-env` v7.23.2\n  - `@babel/helper-define-polyfill-provider` v0.4.3\n  - `babel-plugin-polyfill-corejs2` v0.4.6\n  - `babel-plugin-polyfill-corejs3` v0.8.5\n  - `babel-plugin-polyfill-es-shims` v0.10.0\n  - `babel-plugin-polyfill-regenerator` v0.5.3"),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":10245, "endLine":10245}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code"),
				Desc:  utils.Ptr("### Impact\n\nUsing Babel to compile code that was specifically crafted by an attacker can lead to arbitrary code execution during compilation, when using plugins that rely on the `path.evaluate()`or `path.evaluateTruthy()` internal Babel methods.\n\nKnown affected plugins are:\n- `@babel/plugin-transform-runtime`\n- `@babel/preset-env` when using its [`useBuiltIns`](https://babeljs.io/docs/babel-preset-env#usebuiltins) option\n- Any \"polyfill provider\" plugin that depends on `@babel/helper-define-polyfill-provider`, such as `babel-plugin-polyfill-corejs3`, `babel-plugin-polyfill-corejs2`, `babel-plugin-polyfill-es-shims`, `babel-plugin-polyfill-regenerator`\n\nNo other plugins under the `@babel/` namespace are impacted, but third-party plugins might be.\n\n**Users that only compile trusted code are not impacted.**\n\n### Patches\n\nThe vulnerability has been fixed in `@babel/traverse@7.23.2`.\n\nBabel 6 does not receive security fixes anymore (see [Babel's security policy](https://github.com/babel/babel/security/policy)), hence there is no patch planned for `babel-traverse@6`.\n\n### Workarounds\n\n- Upgrade `@babel/traverse` to v7.23.2 or higher. You can do this by deleting it from your package manager's lockfile and re-installing the dependencies. `@babel/core` \u003e=7.23.2 will automatically pull in a non-vulnerable version.\n- If you cannot upgrade `@babel/traverse` and are using one of the affected packages mentioned above, upgrade them to their latest version to avoid triggering the vulnerable code path in affected `@babel/traverse` versions:\n  - `@babel/plugin-transform-runtime` v7.23.2\n  - `@babel/preset-env` v7.23.2\n  - `@babel/helper-define-polyfill-provider` v0.4.3\n  - `babel-plugin-polyfill-corejs2` v0.4.6\n  - `babel-plugin-polyfill-corejs3` v0.8.5\n  - `babel-plugin-polyfill-es-shims` v0.10.0\n  - `babel-plugin-polyfill-regenerator` v0.5.3"),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2023-45133"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "babel-traverse", Version: "6.11.4"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(10245)),
						EndLine:   utils.Ptr(int32(10245)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String()),
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:         "CVE-2020-8244",
			Title:       "Remote Memory Exposure in bl",
			Desc:        utils.Ptr("A buffer over-read vulnerability exists in bl \u003c4.0.3, \u003c3.0.1, \u003c2.2.1, and \u003c1.2.3 which could allow an attacker to supply user input (even typed) that if it ends up in consume() argument and can become negative, the BufferList state can be corrupted, tricking it into exposing uninitialized memory via regular .slice() calls."),
			DataSources: []string{`{"targetType":"TARGET_TYPE_REPOSITORY", "uri":{"uriSchema":"URI_SCHEMA_FILE", "path":"testdata/javascript/package-lock.json"}, "fileFindingLocationData":{"startLine":586, "endLine":586}, "sourceCodeMetadata":{"repositoryUrl":"https://github.com/0c34/govwa", "reference":"master"}}`},
			ProductUid:  utils.Ptr("osv-scanner"),
		},
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Remote Memory Exposure in bl"),
				Desc:  utils.Ptr("A buffer over-read vulnerability exists in bl \u003c4.0.3, \u003c3.0.1, \u003c2.2.1, and \u003c1.2.3 which could allow an attacker to supply user input (even typed) that if it ends up in consume() argument and can become negative, the BufferList state can be corrupted, tricking it into exposing uninitialized memory via regular .slice() calls."),
				Cve:   &ocsfv1.Cve{Uid: "CVE-2020-8244"},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "bl", Version: "1.0.3"},
				},
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						File: &ocsfv1.File{
							Name: "package-lock.json",
							Path: utils.Ptr("testdata/javascript/package-lock.json"),
						},
						StartLine: utils.Ptr(int32(586)),
						EndLine:   utils.Ptr(int32(586)),
					},
				},
			},
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
	},
}
