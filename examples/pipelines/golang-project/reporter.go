package main

import (
	"context"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type jsonReporter struct{}

func (j jsonReporter) Report(
	ctx context.Context,
	findings []*ocsf.VulnerabilityFinding,
) error {
	return nil
}
