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

type sampleFilter struct{}

func (s sampleFilter) Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
	component.LoggerFromContext(ctx).Info("Filter.")
	return make([]*ocsf.VulnerabilityFinding, 0, 80), true, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	storageManager, err := local.NewStoreManager()
	if err != nil {
		log.Fatalf("failed to create storage manager: %v", err)
	}

	if err := component.RunFilter(
		ctx,
		sampleFilter{},
		component.RunnerWithComponentName("sample-filter"),
		component.RunnerWithStorer("local", storageManager),
		component.RunnerWithWorkflowID(uuid.New()),
	); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
