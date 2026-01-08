package findingsclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/utils"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	v1 "github.com/smithy-security/smithy/sdk/gen/findings_service/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
)

const (
	defaultClientMaxAttempts                  = 10
	defaultClientInitialBackoffSeconds        = "5s"
	defaultClientMaxBackoffSeconds            = "60s"
	defaultClientBackoffMultiplier            = 1.5
	defaultClientPageSize              uint32 = 100
)

type (
	client struct {
		pageSize          uint32
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

	clientPageSize, err := env.GetOrDefault(
		"SMITHY_REMOTE_CLIENT_PAGE_SIZE",
		defaultClientPageSize,
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	return &client{
		pageSize:          clientPageSize,
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
func (c *client) Read(ctx context.Context, instanceID uuid.UUID, queryOpts *store.QueryOpts) ([]*vf.VulnerabilityFinding, error) {
	findingBatches := [][]*v1.Finding{}
	if queryOpts == nil {
		// We impose our own paging in this case
	pageLoop:
		for page := uint32(0); ; page++ {
			pageFindings, err := c.read(ctx, instanceID, &store.QueryOpts{
				Page:     page,
				PageSize: c.pageSize,
			})
			switch {
			case errors.Is(store.ErrNoFindingsFound, err) && page > 0:
				break pageLoop
			case err != nil:
				return nil, err
			case len(pageFindings) < int(c.pageSize):
				findingBatches = append(findingBatches, pageFindings)
				break pageLoop
			default:
				findingBatches = append(findingBatches, pageFindings)
			}
		}
	} else {
		pageFindings, err := c.read(ctx, instanceID, queryOpts)
		if err != nil {
			return nil, err
		}
		findingBatches = append(findingBatches, pageFindings)
	}

	vfs := slices.Collect(utils.MapSlice(
		utils.CollectSlices(findingBatches),
		func(finding *v1.Finding) *vf.VulnerabilityFinding {
			return &vf.VulnerabilityFinding{
				Finding: finding.GetDetails(),
				ID:      finding.GetId(),
			}
		}))
	return vfs, nil
}

func (c *client) read(
	ctx context.Context,
	instanceID uuid.UUID,
	queryOpts *store.QueryOpts,
) ([]*v1.Finding, error) {
	resp, err := c.findingsSvcClient.GetFindings(
		ctx,
		&v1.GetFindingsRequest{
			Id:       instanceID.String(),
			Page:     &queryOpts.Page,
			PageSize: &queryOpts.PageSize,
		},
	)
	if err != nil {
		return nil, errors.Errorf("could not get findings: %w", c.checkErr(err))
	}

	switch {
	case resp == nil:
		return nil, errors.New("unexpected nil response")
	case len(resp.Findings) == 0:
		return nil, store.ErrNoFindingsFound
	default:
		return resp.Findings, nil
	}
}

// Update updates findings by instanceID.
func (c *client) Update(ctx context.Context, instanceID uuid.UUID, findings []*vf.VulnerabilityFinding) error {
	logger := sdklogger.LoggerFromContext(ctx)

	pageNo := 1
	findingsPageIterator := utils.MapSlice(
		slices.Chunk(findings, int(c.pageSize)),
		func(page []*vf.VulnerabilityFinding) []*v1.Finding {
			vf := []*v1.Finding{}
			for _, finding := range page {
				vf = append(vf, &v1.Finding{
					Id:      finding.ID,
					Details: finding.Finding,
				})
			}
			return vf
		},
	)
	for findingsPage := range findingsPageIterator {
		logger.Info("submitting page of findings", slog.Int("pageNo", pageNo), slog.Int("pageSize", len(findingsPage)))

		if _, err := c.findingsSvcClient.UpdateFindings(
			ctx,
			&v1.UpdateFindingsRequest{
				Id:       instanceID.String(),
				Findings: findingsPage,
			},
		); err != nil {
			return errors.Errorf("could not update findings: %w", c.checkErr(err))
		}
	}

	return nil
}

// Write creates findings by instanceID.
func (c *client) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	if len(findings) == 0 {
		return status.Error(codes.InvalidArgument, "no findings provided")
	}

	logger := sdklogger.LoggerFromContext(ctx)

	pageNo := 1
	for page := range slices.Chunk(findings, int(c.pageSize)) {
		logger.Info("submitting batch of findings", slog.Int("pageNo", pageNo), slog.Int("pageSize", len(page)))

		if _, err := c.findingsSvcClient.CreateFindings(
			ctx,
			&v1.CreateFindingsRequest{
				Id:       instanceID.String(),
				Findings: page,
			},
		); err != nil {
			return errors.Errorf("could not update findings: %w", c.checkErr(err))
		}

		pageNo += 1
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
