package main

import (
	"context"
	"log"
	"time"

	_ "github.com/bwmarrin/discordgo"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/retry"
	"github.com/smithy-security/smithy/sdk/component"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	rc, err := retry.NewClient(
		retry.Config{},
	)
	if err != nil {
		return errors.Errorf("failed to create retry client: %w", err)
	}

	_ = rc

	if err := component.RunReporter(
		ctx,
		nil,
		component.RunnerWithComponentName("discord"),
	); err != nil {
		return errors.Errorf("could not run reporter: %w", err)
	}

	return nil
}
