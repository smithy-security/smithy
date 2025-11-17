package main

import (
	"context"
	"log"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/transformer"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

// Main is the entrypoint to the scanner
func Main(ctx context.Context, opts ...component.RunnerOption) error {
	opts = append(opts, component.RunnerWithComponentName("osv-scanner"))

	cfg, err := config.New()
	if err != nil {
		return errors.Errorf("could not extract configuration values from environment: %w", err)
	}

	osvScannerTranformer, err := transformer.New(cfg)
	if err != nil {
		return errors.Errorf("could not create transformer: %w", err)
	}

	if err := component.RunScanner(ctx, osvScannerTranformer, opts...); err != nil {
		return errors.Errorf("could not run scanner: %w", err)
	}

	return nil
}
