package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/storer/local"
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

	storageManager, err := local.NewStoreManager()
	if err != nil {
		log.Fatalf("failed to create storage manager: %v", err)
	}

	if err := component.RunReporter(
		ctx,
		sampleReporter{},
		component.RunnerWithComponentName("sample-reporter"),
		component.RunnerWithStorer("local", storageManager),
	); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
