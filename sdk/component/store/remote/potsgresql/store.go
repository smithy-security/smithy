package potsgresql

import (
	"context"

	"github.com/smithy-security/smithy/sdk/component/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

// TODO: implement in next PR.
type manager struct{}

func (m manager) Close(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (m manager) Validate(finding *ocsf.VulnerabilityFinding) error {
	//TODO implement me
	panic("implement me")
}

func (m manager) Read(ctx context.Context, instanceID uuid.UUID) ([]*ocsf.VulnerabilityFinding, error) {
	//TODO implement me
	panic("implement me")
}

func (m manager) Update(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	//TODO implement me
	panic("implement me")
}

func (m manager) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	//TODO implement me
	panic("implement me")
}
