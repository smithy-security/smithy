package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleReporter struct{}

func (s sampleReporter) Report(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	component.LoggerFromContext(ctx).Info("Report.")
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunReporter(ctx, sampleReporter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
