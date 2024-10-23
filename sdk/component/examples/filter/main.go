package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleFilter struct{}

func (s sampleFilter) Close(ctx context.Context) error {
	component.LoggerFromContext(ctx).Info("Closing filter.")
	return nil
}

func (s sampleFilter) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Read.")
	return make([]*ocsf.VulnerabilityFinding, 0, 100), nil
}

func (s sampleFilter) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	component.LoggerFromContext(ctx).Info("Update.")
	return nil
}

func (s sampleFilter) Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
	component.LoggerFromContext(ctx).Info("Filter.")
	return make([]*ocsf.VulnerabilityFinding, 0, 80), true, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunFilter(ctx, sampleFilter{}, component.RunnerWithComponentName("sample-filter")); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
