package elixir

import (
	"github.com/smithy-security/pkg/utils"
	ocsfv1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

var Results = []*ocsfv1.VulnerabilityFinding{
	{
		FindingInfo: &ocsfv1.FindingInfo{
			Uid:   "CVE-2020-15150",
			Title: "Remote Code Execution in paginator",
			Desc: utils.Ptr(`There is a vulnerability in Paginator which makes it susceptible to Remote Code Execution (RCE) attacks via input parameters to the "paginate()" function.

### Impact
There is a vulnerability in Paginator which makes it susceptible to Remote Code Execution (RCE) attacks via input parameters to the "paginate()" function. This will potentially affect all current users of "Paginator" prior to version >= 1.0.0.

### Patches
The vulnerability has been patched in version 1.0.0 and all users should upgrade to this version immediately. Note that this patched version uses a dependency that requires an Elixir version >=1.5.

### Credits

Thank you to Peter Stöckli.`),
			DataSources: []string{
				"{\"targetType\":\"TARGET_TYPE_REPOSITORY\",\"uri\":{\"uriSchema\":\"URI_SCHEMA_FILE\",\"path\":\"testdata/elixir/mix.lock\"},\"fileFindingLocationData\":{\"startLine\":22,\"endLine\":22},\"sourceCodeMetadata\":{\"repositoryUrl\":\"https://github.com/0c34/govwa\",\"reference\":\"master\"}}",
			},
			ProductUid: utils.Ptr("osv-scanner"),
		},
		Severity: utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String()),
		Vulnerabilities: []*ocsfv1.Vulnerability{
			{
				Title: utils.Ptr("Remote Code Execution in paginator"),
				Desc: utils.Ptr(`There is a vulnerability in Paginator which makes it susceptible to Remote Code Execution (RCE) attacks via input parameters to the "paginate()" function.

### Impact
There is a vulnerability in Paginator which makes it susceptible to Remote Code Execution (RCE) attacks via input parameters to the "paginate()" function. This will potentially affect all current users of "Paginator" prior to version >= 1.0.0.

### Patches
The vulnerability has been patched in version 1.0.0 and all users should upgrade to this version immediately. Note that this patched version uses a dependency that requires an Elixir version >=1.5.

### Credits

Thank you to Peter Stöckli.`),
				AffectedCode: []*ocsfv1.AffectedCode{
					{
						EndLine: utils.Ptr(int32(22)),
						File: &ocsfv1.File{
							Name: "mix.lock",
							Path: utils.Ptr("testdata/elixir/mix.lock"),
						},
						StartLine: utils.Ptr(int32(22)),
					},
				},
				AffectedPackages: []*ocsfv1.AffectedPackage{
					{Name: "paginator", Version: "0.6.0"},
				},
				Cve: &ocsfv1.Cve{Uid: "CVE-2020-15150"},
			},
		},
	},
}
