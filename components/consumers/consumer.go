// Package consumers provides helper functions for working with Smithy compatible outputs as a Consumer.
// Subdirectories in this package have more complete example usages of this package.
package consumers

import (
	"flag"
	"log/slog"
	"os"

	"github.com/go-errors/errors"

	smithyapiv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components"
	"github.com/smithy-security/smithy/pkg/putil"
)

var (
	inResults string
	// Raw represents if the non-enriched results should be used.
	Raw bool
	// debug flag initializes the logger with a debug level
	debug bool
)

func init() {
	flag.StringVar(&inResults, "in", "", "the directory where smithy producer/enricher outputs are")
	flag.BoolVar(&Raw, "raw", false, "if the non-enriched results should be used")
	flag.BoolVar(&debug, "debug", false, "turn on debug logging")
}

// ParseFlags will parse the input flags for the consumer and perform simple validation.
func ParseFlags() error {
	flag.Parse()

	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})).With("scanID", os.Getenv(components.EnvSmithyScanID)))
	if len(inResults) < 1 {
		return errors.Errorf("in is undefined")
	}
	return nil
}

// LoadToolResponse loads raw results from producers.
func LoadToolResponse() ([]*smithyapiv1.LaunchToolResponse, error) {
	return putil.LoadToolResponse(inResults)
}

// LoadEnrichedToolResponse loads enriched results from the enricher.
func LoadEnrichedToolResponse() ([]*smithyapiv1.EnrichedLaunchToolResponse, error) {
	return putil.LoadEnrichedToolResponse(inResults)
}
