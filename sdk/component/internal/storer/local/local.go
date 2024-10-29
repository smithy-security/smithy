package local

import (
	"context"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// storeManager is going to be the local storage manager backed by SQLite.
type storeManager struct{}

// NewStoreManager returns a new store manager.
func NewStoreManager() (*storeManager, error) {
	return &storeManager{}, nil
}

func (s *storeManager) Close(ctx context.Context) error {
	return nil
}

func (s *storeManager) Validate(finding *ocsf.VulnerabilityFinding) error {
	return nil
}

func (s *storeManager) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

func (s *storeManager) Write(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

func (s *storeManager) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}
