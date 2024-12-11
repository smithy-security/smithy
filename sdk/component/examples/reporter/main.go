package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
)

type sampleReporter struct{}

func (s sampleReporter) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
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
