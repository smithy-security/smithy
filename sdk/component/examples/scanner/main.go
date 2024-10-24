package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type (
	sampleScanner struct{}

	sampleRawVuln struct{}
)

func (s sampleRawVuln) Unmarshal() (*ocsf.VulnerabilityFinding, error) {
	return &ocsf.VulnerabilityFinding{}, nil
}

func (s sampleScanner) Close(ctx context.Context) error {
	component.LoggerFromContext(ctx).Info("Closing scanner.")
	return nil
}

func (s sampleScanner) Store(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	component.LoggerFromContext(ctx).Info("Storing.")
	return nil
}

func (s sampleScanner) Scan(ctx context.Context) ([]component.Unmarshaler, error) {
	component.LoggerFromContext(ctx).Info("Scanning.")
	var rawVulns = make([]component.Unmarshaler, 0, 10)
	for i := 0; i < 10; i++ {
		rawVulns = append(rawVulns, sampleRawVuln{})
	}
	return rawVulns, nil
}

func (s sampleScanner) Transform(ctx context.Context, payload component.Unmarshaler) (*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Transforming.")
	return &ocsf.VulnerabilityFinding{}, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunScanner(ctx, sampleScanner{}, component.RunnerWithComponentName("sample-scanner")); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
