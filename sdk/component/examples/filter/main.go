package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	"github.com/smithy-security/smithy/sdk/logger"
)

type sampleFilter struct{}

func (s sampleFilter) Filter(ctx context.Context, findings []*vf.VulnerabilityFinding) ([]*vf.VulnerabilityFinding, bool, error) {
	logger.LoggerFromContext(ctx).Info("Filter.")
	return make([]*vf.VulnerabilityFinding, 0, 80), true, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunFilter(ctx, sampleFilter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
