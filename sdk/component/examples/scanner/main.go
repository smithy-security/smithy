package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/smithy-security/smithy/sdk/logger"
)

type sampleScanner struct{}

func (s sampleScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger.LoggerFromContext(ctx).Info("Transforming.")
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunScanner(ctx, sampleScanner{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
