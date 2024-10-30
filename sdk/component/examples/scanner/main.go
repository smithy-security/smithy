package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/storer/local"
	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleScanner struct{}

func (s sampleScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	component.LoggerFromContext(ctx).Info("Transforming.")
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	storageManager, err := local.NewStoreManager()
	if err != nil {
		log.Fatalf("failed to create storage manager: %v", err)
	}

	if err := component.RunScanner(
		ctx,
		sampleScanner{},
		component.RunnerWithComponentName("sample-scanner"),
		component.RunnerWithStorer("local", storageManager),
		component.RunnerWithWorkflowID(uuid.New()),
	); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
