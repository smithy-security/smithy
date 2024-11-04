package main

import (
	"context"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type deduplicationEnricher struct{}

func (m deduplicationEnricher) Annotate(
	ctx context.Context,
	findings []*ocsf.VulnerabilityFinding,
) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}
