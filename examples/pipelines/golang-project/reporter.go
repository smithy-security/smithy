package main

import (
	"context"
	"log/slog"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type jsonReporter struct{}

func (j jsonReporter) Report(
	ctx context.Context,
	findings []*ocsf.VulnerabilityFinding,
) error {
	logger := component.LoggerFromContext(ctx)
	for _, finding := range findings {
		b, err := protojson.Marshal(finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}
		logger.Info("found finding", slog.String("finding", string(b)))
	}

	return nil
}
