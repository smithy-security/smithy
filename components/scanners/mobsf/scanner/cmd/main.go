package main

import (
	"context"
	"log"
	"log/slog"

	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/config"
	"github.com/smithy-security/smithy/components/scanners/mobsf/scanner/internal/orchestrator"
)

func main() {
	ctx := context.Background()

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Failed to create config: %v", err)
	}

	mobsf, err := orchestrator.New(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to create MobSF orchestrator: %v", err)
	}

	if err := mobsf.Run(ctx); err != nil {
		log.Fatalf("Application failed: %v", err)
	}

	slog.Info("Application completed successfully")
}
