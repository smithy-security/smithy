package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
)

type sampleTarget struct{}

func (s sampleTarget) Prepare(ctx context.Context) error {
	component.LoggerFromContext(ctx).Info("Preparing.")
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunTarget(
		ctx,
		sampleTarget{},
		component.RunnerWithComponentName("sample-target"),
		component.RunnerWithWorkflowID(uuid.New()),
	); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
