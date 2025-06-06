package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	"github.com/smithy-security/smithy/sdk/logger"
)

type sampleEnricher struct{}

func (s sampleEnricher) Annotate(ctx context.Context, findings []*vf.VulnerabilityFinding) ([]*vf.VulnerabilityFinding, error) {
	logger.LoggerFromContext(ctx).Info("Annotate.")
	return make([]*vf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunEnricher(ctx, sampleEnricher{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
