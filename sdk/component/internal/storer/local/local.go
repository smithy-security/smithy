package local

import (
	"context"

	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// storeManager is going to be the local storage manager backed by SQLite.
type storeManager struct{}

// NewStoreManager returns a new store manager.
func NewStoreManager() (*storeManager, error) {
	return &storeManager{}, nil
}

// TODO - implement me.
func (s *storeManager) Close(ctx context.Context) error {
	return nil
}

// TODO - implement me.
func (s *storeManager) Validate(finding *ocsf.VulnerabilityFinding) error {
	return nil
}

// TODO - implement me.
func (s *storeManager) Read(
	ctx context.Context,
	workflowID uuid.UUID,
) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

// TODO - implement me.
func (s *storeManager) Write(
	ctx context.Context,
	workflowID uuid.UUID,
	findings []*ocsf.VulnerabilityFinding,
) error {
	return nil
}

// TODO - implement me.
func (s *storeManager) Update(
	ctx context.Context,
	workflowID uuid.UUID,
	findings []*ocsf.VulnerabilityFinding,
) error {
	return nil
}
