package testdata

import (
	ocsffindinginfov1 "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

var TargetMetadata = &ocsffindinginfov1.DataSource{
	TargetType: ocsffindinginfov1.DataSource_TARGET_TYPE_REPOSITORY,
	SourceCodeMetadata: &ocsffindinginfov1.DataSource_SourceCodeMetadata{
		RepositoryUrl: "https://github.com/0c34/govwa",
		Reference:     "master",
	},
}
