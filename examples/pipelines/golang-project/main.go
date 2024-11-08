package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
)

const (
	repoPath = "govwa"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatal(err)
	}
}

func Main(ctx context.Context) error {
	if err := migrate(); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	defer func() {
		if err := os.RemoveAll("smithy.db"); err != nil {
			log.Printf("failed to remove sqlite db: %v\n", err)
		}
	}()

	if err := os.Mkdir(repoPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create clone path %s: %v", repoPath, err)
	}

	defer func() {
		if err := os.RemoveAll(repoPath); err != nil {
			log.Printf("failed to remove clone path %s: %v\n", repoPath, err)
		}
	}()

	gitClone, err := NewGitCloneTarget("https://github.com/0c34/govwa.git", repoPath)
	if err != nil {
		return fmt.Errorf("failed to create git clone target: %w", err)
	}

	goSec, err := NewGoSecScanner(repoPath)
	if err != nil {
		return fmt.Errorf("failed to create gosec scanner: %w", err)
	}

	var (
		customAnnotation = &customAnnotationEnricher{}
		jsonLogger       = &jsonReporter{}
	)

	if err := component.RunTarget(
		ctx,
		gitClone,
		component.RunnerWithComponentName("git-clone"),
	); err != nil {
		return fmt.Errorf("target failed: %w", err)
	}

	if err := component.RunScanner(
		ctx,
		goSec,
		component.RunnerWithComponentName("go-sec"),
	); err != nil {
		return fmt.Errorf("scanner failed: %w", err)
	}

	if err := component.RunEnricher(
		ctx,
		customAnnotation,
		component.RunnerWithComponentName("custom-annotation"),
	); err != nil {
		return fmt.Errorf("enricher failed: %w", err)
	}

	if err := component.RunReporter(
		ctx,
		jsonLogger,
		component.RunnerWithComponentName("json-logger"),
	); err != nil {
		return fmt.Errorf("reporter failed: %w", err)
	}

	return nil
}

func ptr[T any](v T) *T {
	return &v
}
