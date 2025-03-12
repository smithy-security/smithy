package findingsclient

import (
	"context"
	"encoding/json"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	v1 "github.com/smithy-security/smithy/sdk/gen/findings_service/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const (
	defaultClientMaxAttempts           = 10
	defaultClientInitialBackoffSeconds = "5s"
	defaultClientMaxBackoffSeconds     = "60s"
	defaultClientBackoffMultiplier     = 1.5
)

type (
	client struct {
		rpcConn           *grpc.ClientConn
		findingsSvcClient v1.FindingsServiceClient
	}

	clientRetry struct {
		MethodConfig []clientMethodConf `json:"methodConfig"`
	}

	clientMethodConf struct {
		Name        []clientRetryMethod `json:"name"`
		RetryPolicy clientRetryPolicy   `json:"retryPolicy"`
	}

	clientRetryMethod struct {
		Service string `json:"service"`
	}

	clientRetryPolicy struct {
		MaxAttempts          int      `json:"maxAttempts"`
		InitialBackoff       string   `json:"initialBackoff"`
		MaxBackoff           string   `json:"maxBackoff"`
		BackoffMultiplier    float64  `json:"backoffMultiplier"`
		RetryableStatusCodes []string `json:"retryableStatusCodes"`
	}
)

// New it returns a new findings' client.
func New() (*client, error) {
	findingsSvcAddr, err := env.GetOrDefault(
		"SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR",
		"localhost:50051",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	retryStr, err := newClientRetryStr()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		findingsSvcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(retryStr),
	)
	if err != nil {
		return nil, errors.Errorf("could not create findings client connection: %v", err)
	}

	return &client{
		rpcConn:           conn,
		findingsSvcClient: v1.NewFindingsServiceClient(conn),
	}, nil
}

// newClientRetryStr returns gRPC retry config per https://grpc.io/docs/guides/retry/.
func newClientRetryStr() (string, error) {
	clientMaxAttempts, err := env.GetOrDefault(
		"SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS",
		defaultClientMaxAttempts,
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return "", err
	}

	clientInitialBackoffSeconds, err := env.GetOrDefault(
		"SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS",
		defaultClientInitialBackoffSeconds,
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return "", err
	}

	clientMaxBackoffSeconds, err := env.GetOrDefault(
		"SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS",
		defaultClientMaxBackoffSeconds,
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return "", err
	}

	clientBackoffMultiplier, err := env.GetOrDefault(
		"SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER",
		defaultClientBackoffMultiplier,
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return "", err
	}

	var retry = clientRetry{
		MethodConfig: []clientMethodConf{
			{
				Name: []clientRetryMethod{
					{
						Service: "findings_service.v1.FindingsService",
					},
				},
				RetryPolicy: clientRetryPolicy{
					MaxAttempts:       clientMaxAttempts,
					InitialBackoff:    clientInitialBackoffSeconds,
					MaxBackoff:        clientMaxBackoffSeconds,
					BackoffMultiplier: clientBackoffMultiplier,
					RetryableStatusCodes: []string{
						"UNAVAILABLE",
					},
				},
			},
		},
	}

	srvRetryBytes, err := json.Marshal(retry)
	if err != nil {
		return "", errors.Errorf("failed to marshal default client retry conf: %w", err)
	}

	return string(srvRetryBytes), nil
}

// Close closes the underlying connection to the findings' client.
func (c *client) Close(ctx context.Context) error {
	if err := c.rpcConn.Close(); err != nil {
		return errors.Errorf("could not close findings client connection: %v", err)
	}
	return nil
}

// Validate validates the passed finding.
// TODO: to be tackled with https://linear.app/smithy/issue/OCU-259/validate-component-input-and-output.
func (c *client) Validate(finding *ocsf.VulnerabilityFinding) error {
	return nil
}

// Read gets findings by instanceID.
func (c *client) Read(ctx context.Context, instanceID uuid.UUID) ([]*vf.VulnerabilityFinding, error) {
	resp, err := c.findingsSvcClient.GetFindings(ctx, &v1.GetFindingsRequest{Id: instanceID.String()})
	if err != nil {
		return nil, errors.Errorf("could not get findings: %w", c.checkErr(err))
	}

	findings := make([]*vf.VulnerabilityFinding, 0, len(resp.Findings))
	for _, finding := range resp.Findings {
		findings = append(
			findings,
			&vf.VulnerabilityFinding{
				Finding: finding.GetDetails(),
				ID:      finding.GetId(),
			},
		)
	}

	return findings, nil
}

// Update updates findings by instanceID.
func (c *client) Update(ctx context.Context, instanceID uuid.UUID, findings []*vf.VulnerabilityFinding) error {
	reqFindings := make([]*v1.Finding, 0, len(findings))
	for _, finding := range findings {
		reqFindings = append(
			reqFindings,
			&v1.Finding{
				Id:      finding.ID,
				Details: finding.Finding,
			},
		)
	}

	if _, err := c.findingsSvcClient.UpdateFindings(
		ctx,
		&v1.UpdateFindingsRequest{
			Id:       instanceID.String(),
			Findings: reqFindings,
		},
	); err != nil {
		return errors.Errorf("could not update findings: %w", c.checkErr(err))
	}

	return nil
}

// Write creates findings by instanceID.
func (c *client) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	if _, err := c.findingsSvcClient.CreateFindings(
		ctx,
		&v1.CreateFindingsRequest{
			Id:       instanceID.String(),
			Findings: findings,
		},
	); err != nil {
		return errors.Errorf("could not update findings: %w", c.checkErr(err))
	}
	return nil
}

func (c *client) checkErr(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.NotFound:
		return store.ErrNoFindingsFound
	}

	return errors.Errorf("unexpected error with code %s: %w", st.Code().String(), err)
}
