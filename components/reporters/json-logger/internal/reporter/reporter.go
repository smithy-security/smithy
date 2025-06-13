package reporter

import (
	"context"
	"log/slog"

	"github.com/go-errors/errors"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// NewJsonLogger returns a new json logger.
func NewJsonLogger() jsonLogger {
	return jsonLogger{}
}

type jsonLogger struct{}

// Report logs the findings in json format.
func (j jsonLogger) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	for _, finding := range findings {
		b, err := protojson.Marshal(finding.Finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}
		logger.Info("found finding", slog.String("finding", string(b)))
	}

	return nil
}
