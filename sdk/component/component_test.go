package component_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type (
	testTarget struct{}

	testScanner struct{}

	testEnricher struct{}

	testReporter struct{}

	testFilter struct{}
)

func (t testFilter) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testFilter) Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
	return nil, false, nil
}

func (t testFilter) Close(ctx context.Context) error {
	return nil
}

func (t testFilter) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (t testReporter) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testReporter) Report(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (t testReporter) Close(ctx context.Context) error {
	return nil
}

func (t testEnricher) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testEnricher) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (t testEnricher) Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testEnricher) Close(ctx context.Context) error {
	return nil
}

func (t testScanner) Store(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (t testScanner) Scan(ctx context.Context) ([]component.Unmarshaler, error) {
	return nil, nil
}

func (t testScanner) Transform(ctx context.Context, payload component.Unmarshaler) (*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (t testScanner) Close(ctx context.Context) error {
	return nil
}

func (t testTarget) Prepare(ctx context.Context) error {
	return nil
}

func (t testTarget) Close(ctx context.Context) error {
	return nil
}

func TestImplementations(t *testing.T) {
	assert.Implements(t, (*component.Target)(nil), testTarget{})
	assert.Implements(t, (*component.Scanner)(nil), testScanner{})
	assert.Implements(t, (*component.Enricher)(nil), testEnricher{})
	assert.Implements(t, (*component.Reporter)(nil), testReporter{})
	assert.Implements(t, (*component.Filter)(nil), testFilter{})
}
