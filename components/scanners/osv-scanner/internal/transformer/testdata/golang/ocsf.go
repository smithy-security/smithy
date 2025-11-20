package golang

import (
	"github.com/smithy-security/pkg/utils"
	ocsfv1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

var Results = []*ocsfv1.VulnerabilityFinding{
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22869",
			Title: "Potential denial of service in golang.org/x/crypto",
			Desc:  utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":56,\"endLine\":56},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Potential denial of service in golang.org/x/crypto"),
				Desc:  utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(56)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(56)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "golang.org/x/crypto", Version: "0.32.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22869"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22869",
			Title: "golang.org/x/crypto Vulnerable to Denial of Service (DoS) via Slow or Incomplete Key Exchange",
			Desc:  utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":56,\"endLine\":56},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("golang.org/x/crypto Vulnerable to Denial of Service (DoS) via Slow or Incomplete Key Exchange"),
				Desc:  utils.Ptr("SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read into memory, but never transmitted."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(56)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(56)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "golang.org/x/crypto", Version: "0.32.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22869"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22870",
			Title: "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net",
			Desc:  utils.Ptr("Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to \"*.example.com\", a request to \"[::1%25.example.com]:80` will incorrectly match and not be proxied."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":58,\"endLine\":58},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"),
				Desc:  utils.Ptr("Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to \"*.example.com\", a request to \"[::1%25.example.com]:80` will incorrectly match and not be proxied."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(58)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(58)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "golang.org/x/net", Version: "0.34.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22870"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22872",
			Title: "Incorrect Neutralization of Input During Web Page Generation in x/net in golang.org/x/net",
			Desc:  utils.Ptr("The tokenizer incorrectly interprets tags with unquoted attribute values that end with a solidus character (/) as self-closing. When directly using Tokenizer, this can result in such tags incorrectly being marked as self-closing, and when using the Parse functions, this can result in content following such tags as being placed in the wrong scope during DOM construction, but only when tags are in foreign content (e.g. <math>, <svg>, etc contexts)."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":58,\"endLine\":58},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Incorrect Neutralization of Input During Web Page Generation in x/net in golang.org/x/net"),
				Desc:  utils.Ptr("The tokenizer incorrectly interprets tags with unquoted attribute values that end with a solidus character (/) as self-closing. When directly using Tokenizer, this can result in such tags incorrectly being marked as self-closing, and when using the Parse functions, this can result in content following such tags as being placed in the wrong scope during DOM construction, but only when tags are in foreign content (e.g. <math>, <svg>, etc contexts)."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(58)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(58)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "golang.org/x/net", Version: "0.34.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22872"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22872",
			Title: "golang.org/x/net vulnerable to Cross-site Scripting",
			Desc:  utils.Ptr("The tokenizer incorrectly interprets tags with unquoted attribute values that end with a solidus character (/) as self-closing. When directly using Tokenizer, this can result in such tags incorrectly being marked as self-closing, and when using the Parse functions, this can result in content following such tags as being placed in the wrong scope during DOM construction, but only when tags are in foreign content (e.g. <math>, <svg>, etc contexts)."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":58,\"endLine\":58},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("golang.org/x/net vulnerable to Cross-site Scripting"),
				Desc:  utils.Ptr("The tokenizer incorrectly interprets tags with unquoted attribute values that end with a solidus character (/) as self-closing. When directly using Tokenizer, this can result in such tags incorrectly being marked as self-closing, and when using the Parse functions, this can result in content following such tags as being placed in the wrong scope during DOM construction, but only when tags are in foreign content (e.g. <math>, <svg>, etc contexts)."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(58)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(58)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "golang.org/x/net", Version: "0.34.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22872"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2024-45341",
			Title: "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509",
			Desc:  utils.Ptr("A certificate with a URI which has a IPv6 address with a zone ID may incorrectly satisfy a URI name constraint that applies to the certificate chain.\n\nCertificates containing URIs are not permitted in the web PKI, so this only affects users of private PKIs which make use of URIs."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"),
				Desc:  utils.Ptr("A certificate with a URI which has a IPv6 address with a zone ID may incorrectly satisfy a URI name constraint that applies to the certificate chain.\n\nCertificates containing URIs are not permitted in the web PKI, so this only affects users of private PKIs which make use of URIs."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2024-45341"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2024-45336",
			Title: "Sensitive headers incorrectly sent after cross-domain redirect in net/http",
			Desc:  utils.Ptr("The HTTP client drops sensitive headers after following a cross-domain redirect. For example, a request to a.com/ containing an Authorization header which is redirected to b.com/ will not send that header to b.com.\n\nIn the event that the client received a subsequent same-domain redirect, however, the sensitive headers would be restored. For example, a chain of redirects from a.com/, to b.com/1, and finally to b.com/2 would incorrectly send the Authorization header to b.com/2."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Sensitive headers incorrectly sent after cross-domain redirect in net/http"),
				Desc:  utils.Ptr("The HTTP client drops sensitive headers after following a cross-domain redirect. For example, a request to a.com/ containing an Authorization header which is redirected to b.com/ will not send that header to b.com.\n\nIn the event that the client received a subsequent same-domain redirect, however, the sensitive headers would be restored. For example, a chain of redirects from a.com/, to b.com/1, and finally to b.com/2 would incorrectly send the Authorization header to b.com/2."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2024-45336"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22866",
			Title: "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec",
			Desc:  utils.Ptr("Due to the usage of a variable time instruction in the assembly implementation of an internal function, a small number of bits of secret scalars are leaked on the ppc64le architecture. Due to the way this function is used, we do not believe this leakage is enough to allow recovery of the private key when P-256 is used in any well known protocols."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"),
				Desc:  utils.Ptr("Due to the usage of a variable time instruction in the assembly implementation of an internal function, a small number of bits of secret scalars are leaked on the ppc64le architecture. Due to the way this function is used, we do not believe this leakage is enough to allow recovery of the private key when P-256 is used in any well known protocols."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22866"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-22871",
			Title: "Request smuggling due to acceptance of invalid chunked data in net/http",
			Desc:  utils.Ptr("The net/http package improperly accepts a bare LF as a line terminator in chunked data chunk-size lines. This can permit request smuggling if a net/http server is used in conjunction with a server that incorrectly accepts a bare LF as part of a chunk-ext."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Request smuggling due to acceptance of invalid chunked data in net/http"),
				Desc:  utils.Ptr("The net/http package improperly accepts a bare LF as a line terminator in chunked data chunk-size lines. This can permit request smuggling if a net/http server is used in conjunction with a server that incorrectly accepts a bare LF as part of a chunk-ext."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-22871"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-0913",
			Title: "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall",
			Desc:  utils.Ptr("os.OpenFile(path, os.O_CREATE|O_EXCL) behaved differently on Unix and Windows systems when the target path was a dangling symlink. On Unix systems, OpenFile with O_CREATE and O_EXCL flags never follows symlinks. On Windows, when the target path was a symlink to a nonexistent location, OpenFile would create a file in that location. OpenFile now always returns an error when the O_CREATE and O_EXCL flags are both set and the target path is a symlink."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"),
				Desc:  utils.Ptr("os.OpenFile(path, os.O_CREATE|O_EXCL) behaved differently on Unix and Windows systems when the target path was a dangling symlink. On Unix systems, OpenFile with O_CREATE and O_EXCL flags never follows symlinks. On Windows, when the target path was a symlink to a nonexistent location, OpenFile would create a file in that location. OpenFile now always returns an error when the O_CREATE and O_EXCL flags are both set and the target path is a symlink."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-0913"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-4673",
			Title: "Sensitive headers not cleared on cross-origin redirect in net/http",
			Desc:  utils.Ptr("Proxy-Authorization and Proxy-Authenticate headers persisted on cross-origin redirects potentially leaking sensitive information."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Sensitive headers not cleared on cross-origin redirect in net/http"),
				Desc:  utils.Ptr("Proxy-Authorization and Proxy-Authenticate headers persisted on cross-origin redirects potentially leaking sensitive information."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-4673"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-47907",
			Title: "Incorrect results returned from Rows.Scan in database/sql",
			Desc:  utils.Ptr("Cancelling a query (e.g. by cancelling the context passed to one of the query methods) during a call to the Scan method of the returned Rows can result in unexpected results if other queries are being made in parallel. This can result in a race condition that may overwrite the expected results with those of another query, causing the call to Scan to return either unexpected results from the other query or an error."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Incorrect results returned from Rows.Scan in database/sql"),
				Desc:  utils.Ptr("Cancelling a query (e.g. by cancelling the context passed to one of the query methods) during a call to the Scan method of the returned Rows can result in unexpected results if other queries are being made in parallel. This can result in a race condition that may overwrite the expected results with those of another query, causing the call to Scan to return either unexpected results from the other query or an error."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-47907"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-47906",
			Title: "Unexpected paths returned from LookPath in os/exec",
			Desc:  utils.Ptr("If the PATH environment variable contains paths which are executables (rather than just directories), passing certain strings to LookPath (\"\", \".\", and \"..\"), can result in the binaries listed in the PATH being unexpectedly returned."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Unexpected paths returned from LookPath in os/exec"),
				Desc:  utils.Ptr("If the PATH environment variable contains paths which are executables (rather than just directories), passing certain strings to LookPath (\"\", \".\", and \"..\"), can result in the binaries listed in the PATH being unexpectedly returned."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-47906"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-61725",
			Title: "Excessive CPU consumption in ParseAddress in net/mail",
			Desc:  utils.Ptr("The ParseAddress function constructeds domain-literal address components through repeated string concatenation. When parsing large domain-literal components, this can cause excessive CPU consumption."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Excessive CPU consumption in ParseAddress in net/mail"),
				Desc:  utils.Ptr("The ParseAddress function constructeds domain-literal address components through repeated string concatenation. When parsing large domain-literal components, this can cause excessive CPU consumption."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-61725"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58187",
			Title: "Quadratic complexity when checking name constraints in crypto/x509",
			Desc:  utils.Ptr("Due to the design of the name constraint checking algorithm, the processing time of some inputs scals non-linearly with respect to the size of the certificate.\n\nThis affects programs which validate arbitrary certificate chains."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Quadratic complexity when checking name constraints in crypto/x509"),
				Desc:  utils.Ptr("Due to the design of the name constraint checking algorithm, the processing time of some inputs scals non-linearly with respect to the size of the certificate.\n\nThis affects programs which validate arbitrary certificate chains."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58187"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58189",
			Title: "ALPN negotiation error contains attacker controlled information in crypto/tls",
			Desc:  utils.Ptr("When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("ALPN negotiation error contains attacker controlled information in crypto/tls"),
				Desc:  utils.Ptr("When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58189"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-61723",
			Title: "Quadratic complexity when parsing some invalid inputs in encoding/pem",
			Desc:  utils.Ptr("The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input.\n\nThis affects programs which parse untrusted PEM inputs."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Quadratic complexity when parsing some invalid inputs in encoding/pem"),
				Desc:  utils.Ptr("The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input.\n\nThis affects programs which parse untrusted PEM inputs."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-61723"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-47912",
			Title: "Insufficient validation of bracketed IPv6 hostnames in net/url",
			Desc:  utils.Ptr("The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: \"http://[::1]/\". IPv4 addresses and hostnames must not appear within square brackets. Parse did not enforce this requirement."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Insufficient validation of bracketed IPv6 hostnames in net/url"),
				Desc:  utils.Ptr("The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: \"http://[::1]/\". IPv4 addresses and hostnames must not appear within square brackets. Parse did not enforce this requirement."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-47912"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58185",
			Title: "Parsing DER payload can cause memory exhaustion in encoding/asn1",
			Desc:  utils.Ptr("Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Parsing DER payload can cause memory exhaustion in encoding/asn1"),
				Desc:  utils.Ptr("Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58185"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58186",
			Title: "Lack of limit when parsing cookies can cause memory exhaustion in net/http",
			Desc:  utils.Ptr("Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does not have a limit. By sending a lot of very small cookies such as \"a=;\", an attacker can make an HTTP server allocate a large amount of structs, causing large memory consumption."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Lack of limit when parsing cookies can cause memory exhaustion in net/http"),
				Desc:  utils.Ptr("Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does not have a limit. By sending a lot of very small cookies such as \"a=;\", an attacker can make an HTTP server allocate a large amount of structs, causing large memory consumption."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58186"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58188",
			Title: "Panic when validating certificates with DSA public keys in crypto/x509",
			Desc:  utils.Ptr("Validating certificate chains which contain DSA public keys can cause programs to panic, due to a interface cast that assumes they implement the Equal method.\n\nThis affects programs which validate arbitrary certificate chains."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Panic when validating certificates with DSA public keys in crypto/x509"),
				Desc:  utils.Ptr("Validating certificate chains which contain DSA public keys can cause programs to panic, due to a interface cast that assumes they implement the Equal method.\n\nThis affects programs which validate arbitrary certificate chains."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58188"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-58183",
			Title: "Unbounded allocation when parsing GNU sparse map in archive/tar",
			Desc:  utils.Ptr("tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0 sparse files. A maliciously-crafted archive containing a large number of sparse regions can cause a Reader to read an unbounded amount of data from the archive into memory. When reading from a compressed source, a small compressed input can result in large allocations."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Unbounded allocation when parsing GNU sparse map in archive/tar"),
				Desc:  utils.Ptr("tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0 sparse files. A maliciously-crafted archive containing a large number of sparse regions can cause a Reader to read an unbounded amount of data from the archive into memory. When reading from a compressed source, a small compressed input can result in large allocations."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-58183"},
			},
		},
	},
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2025-61724",
			Title: "Excessive CPU consumption in Reader.ReadResponse in net/textproto",
			Desc:  utils.Ptr("The Reader.ReadResponse function constructs a response string through repeated string concatenation of lines. When the number of lines in a response is large, this can cause excessive CPU consumption."),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/golang/go.mod\"},\"fileFindingLocationData\":{\"startLine\":3,\"endLine\":3},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Excessive CPU consumption in Reader.ReadResponse in net/textproto"),
				Desc:  utils.Ptr("The Reader.ReadResponse function constructs a response string through repeated string concatenation of lines. When the number of lines in a response is large, this can cause excessive CPU consumption."),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(3)),
						File: &ocsfv1.File{
							Name: "go.mod",
							Path: utils.Ptr("testdata/golang/go.mod"),
						},
						StartLine: utils.Ptr(int32(3)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "stdlib", Version: "1.23.4"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2025-61724"},
			},
		},
	},
}
