package component_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/smithy/sdk/component"
	finding "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	testTarget struct{}

	testScanner struct{}

	testEnricher struct{}

	testReporter struct{}

	testFilter struct{}
)

func (t testFilter) Filter(
	ctx context.Context,
	findings []*finding.VulnerabilityFinding,
) ([]*finding.VulnerabilityFinding, bool, error) {
	return nil, true, nil
}

func (t testReporter) Report(ctx context.Context, findings []*finding.VulnerabilityFinding) error {
	return nil
}

func (t testEnricher) Annotate(
	ctx context.Context,
	findings []*finding.VulnerabilityFinding,
) ([]*finding.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testTarget) Prepare(ctx context.Context) error {
	return nil
}

func TestImplementations(t *testing.T) {
	assert.Implements(t, (*component.Target)(nil), testTarget{})
	assert.Implements(t, (*component.Scanner)(nil), testScanner{})
	assert.Implements(t, (*component.Enricher)(nil), testEnricher{})
	assert.Implements(t, (*component.Reporter)(nil), testReporter{})
	assert.Implements(t, (*component.Filter)(nil), testFilter{})
}
