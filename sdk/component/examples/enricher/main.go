package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleEnricher struct{}

func (s sampleEnricher) Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Annotate.")
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunEnricher(ctx, sampleEnricher{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
