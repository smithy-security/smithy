package sarif

import (
	"os"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/sarif"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
)

// NewTransformer returns a new initialised sarif transformer.
func NewTransformer(
	rawFindingsPath string,
	clock clockwork.Clock,
) (*sarif.SarifTransformer, error) {
	guidProvider, err := sarif.NewBasicStableUUIDProvider()
	if err != nil {
		return nil, errors.Errorf("failed to initialize uuid provider: %w", err)
	}

	fileContents, err := os.ReadFile(rawFindingsPath)
	if err != nil {
		return nil, errors.Errorf("could not read file %s", rawFindingsPath)
	}

	var report sarifschemav210.SchemaJson
	if err := report.UnmarshalJSON(fileContents); err != nil {
		return nil, errors.Errorf("failed to parse raw findings output: %w", err)
	}

	return sarif.NewTransformer(
		&report,
		"",
		clock,
		guidProvider,
		true,
	)
}
