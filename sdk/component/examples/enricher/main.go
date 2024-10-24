package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleEnricher struct{}

func (s sampleEnricher) Close(ctx context.Context) error {
	component.LoggerFromContext(ctx).Info("Closing enricher.")
	return nil
}

func (s sampleEnricher) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Read.")
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func (s sampleEnricher) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	component.LoggerFromContext(ctx).Info("Update.")
	return nil
}

func (s sampleEnricher) Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Annotate.")
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunEnricher(ctx, sampleEnricher{}, component.RunnerWithComponentName("sample-enricher")); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
