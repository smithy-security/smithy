package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	"github.com/smithy-security/smithy/sdk/logger"
)

type sampleReporter struct{}

func (s sampleReporter) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger.LoggerFromContext(ctx).Info("Report.")
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunReporter(ctx, sampleReporter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
