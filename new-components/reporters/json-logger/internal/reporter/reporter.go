package reporter

import (
	"context"
	"log/slog"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// NewJsonLogger returns a new json logger.
func NewJsonLogger() jsonLogger {
	return jsonLogger{}
}

type jsonLogger struct{}

// Report logs the findings in json format.
func (j jsonLogger) Report(
	ctx context.Context,
	findings []*ocsf.VulnerabilityFinding,
) error {
	logger := component.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	for _, finding := range findings {
		b, err := protojson.Marshal(finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}
		logger.Info("found finding", slog.String("finding", string(b)))
	}

	return nil
}
