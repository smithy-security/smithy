package component

import (
	"context"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// Helpers interfaces for common functionalities.
type (
	// Validator allows validating vulnerability findings by a specified criteria.
	Validator interface {
		// Validate validates the supplied vulnerability finding and returns an error if invalid.
		Validate(finding *ocsf.VulnerabilityFinding) error
	}

	// Reader allows reading vulnerability findings from a storage.
	Reader interface {
		// Read reads vulnerability findings from a storage.
		Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error)
	}

	// Storer allows storing vulnerability findings in an underlying storage.
	Storer interface {
		// Store stores vulnerability findings.
		Store(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error
	}

	// Updater allows updating vulnerability findings in an underlying storage.
	Updater interface {
		// Update updates existing vulnerability findings.
		Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error
	}

	// Unmarshaler allows defining behaviours to unmarshal data into vulnerability findings format.
	Unmarshaler interface {
		// Unmarshal unmarshals the receiver into vulnerability finding.
		Unmarshal() (*ocsf.VulnerabilityFinding, error)
	}

	// Closer allows to define behaviours to close component dependencies gracefully.
	Closer interface {
		// Close can be implemented to gracefully close component dependencies.
		Close(context.Context) error
	}
)

// Components interfaces.
type (
	// Target prepares the workflow environment.
	Target interface {
		Closer

		// Prepare prepares the target to be scanned.
		Prepare(ctx context.Context) error
	}

	// Scanner scans a target and produces vulnerability findings.
	Scanner interface {
		Closer
		Storer

		// Scan performs a scan on the prepared target and returns raw data.
		Scan(ctx context.Context) ([]Unmarshaler, error)
		// Transform transforms the raw data into vulnerability finding format.
		Transform(ctx context.Context, payload Unmarshaler) (*ocsf.VulnerabilityFinding, error)
	}

	// Filter allows filtering out vulnerability findings by some criteria.
	Filter interface {
		Closer
		Reader
		Updater

		// Filter returns filtered findings from the supplied ones applying some criteria.
		// It returns false if no findings have been filtered out.
		Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error)
	}

	// Enricher allows enriching vulnerability findings by some criteria.
	Enricher interface {
		Closer
		Reader
		Updater

		// Annotate enriches vulnerability findings by some criteria.
		Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error)
	}

	// Reporter advertises behaviours for reporting vulnerability findings.
	Reporter interface {
		Closer
		Reader

		// Report reports vulnerability findings on a specified destination.
		// i.e. raises them as tickets on your favourite ticketing system.
		Report(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error
	}
)
