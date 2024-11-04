package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := migrate(); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	var (
		gitClone      = &gitCloneTarget{}
		goSec         = &goSecScanner{}
		deduplication = &deduplicationEnricher{}
		jsonLogger    = &jsonReporter{}
	)

	if err := component.RunTarget(
		ctx,
		gitClone,
		component.RunnerWithComponentName("git-clone"),
	); err != nil {
		log.Fatalf("target failed: %v", err)
	}

	if err := component.RunScanner(
		ctx,
		goSec,
		component.RunnerWithComponentName("go-sec"),
	); err != nil {
		log.Fatalf("scanner failed: %v", err)
	}

	if err := component.RunEnricher(
		ctx,
		deduplication,
		component.RunnerWithComponentName("deduplication"),
	); err != nil {
		log.Fatalf("enricher failed: %v", err)
	}

	if err := component.RunReporter(
		ctx,
		jsonLogger,
		component.RunnerWithComponentName("json-logger"),
	); err != nil {
		log.Fatalf("reporter failed: %v", err)
	}
}
