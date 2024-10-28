package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/storer/local"
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

	storageManager, err := local.NewStoreManager()
	if err != nil {
		log.Fatalf("failed to create storage manager: %v", err)
	}

	if err := component.RunEnricher(
		ctx,
		sampleEnricher{},
		component.RunnerWithComponentName("sample-enricher"),
		component.RunnerWithStorer("local", storageManager),
	); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
