package main

import (
	"context"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type goSecScanner struct{}

func (g goSecScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}
