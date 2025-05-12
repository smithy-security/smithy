package postgresql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-errors/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/store/remote/postgresql/sqlc"
	_ "github.com/smithy-security/smithy/sdk/component/store/remote/postgresql/sqlc/migrations"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	manager struct {
		clock   clockwork.Clock
		conn    *pgx.Conn
		connDSN string
		queries *sqlc.Queries
	}

	managerOption func(*manager) error
)

// ManagerWithClock allows customising the manager with a clock.
func ManagerWithClock(clock clockwork.Clock) managerOption {
	return func(m *manager) error {
		if clock == nil {
			return errors.New("invalid nil clock")
		}
		m.clock = clock
		return nil
	}
}

// ManagerWithConnDSN allows customising the manager with a dsn.
func ManagerWithConnDSN(dsn string) managerOption {
	return func(m *manager) error {
		if dsn == "" {
			return errors.New("invalid empty dsn")
		}
		m.connDSN = dsn
		return nil
	}
}

// NewManager returns a new manager that is initialised by looking at environment variables and applying customisation.
func NewManager(ctx context.Context, opts ...managerOption) (*manager, error) {
	dsn, err := env.GetOrDefault(
		"SMITHY_REMOTE_STORE_POSTGRES_DSN",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	mgr := &manager{
		clock:   clockwork.NewRealClock(),
		connDSN: dsn,
	}

	for _, opt := range opts {
		if err := opt(mgr); err != nil {
			return nil, errors.Errorf("could not apply options: %w", err)
		}
	}

	connConfig, err := pgx.ParseConfig(mgr.connDSN)
	if err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	mgr.conn, err = pgx.ConnectConfig(
		ctx,
		connConfig,
	)
	if err != nil {
		return nil, errors.Errorf("failed to connect to postgresql database: %w", err)
	}

	mgr.queries = sqlc.New(mgr.conn)
	return mgr, nil
}

// Validate validates the passed finding.
// TODO: to be tackled with https://linear.app/smithy/issue/OCU-259/validate-component-input-and-output.
func (m *manager) Validate(finding *ocsf.VulnerabilityFinding) error {
	return nil
}

// Read finds Vulnerability Findings by instanceID.
// It returns ErrNoFindingsFound is not vulnerabilities were found.
func (m *manager) Read(ctx context.Context, instanceID uuid.UUID) ([]*vf.VulnerabilityFinding, error) {
	rows, err := m.queries.FindingsByID(ctx, m.newPgUUID(instanceID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNoFindingsFound
		}
		return nil, errors.Errorf("failed to read findings: %w", err)
	}

	var findings = make([]*vf.VulnerabilityFinding, 0, len(rows))
	for _, row := range rows {
		var jsonFinding json.RawMessage
		if err := json.Unmarshal(row.Details, &jsonFinding); err != nil {
			return nil, errors.Errorf("could not unmarshal json findings to json.RawMessage: %w", err)
		}

		var finding ocsf.VulnerabilityFinding
		if err := protojson.Unmarshal(jsonFinding, &finding); err != nil {
			return nil, errors.Errorf("failed to unmarshal JSON findings to *ocsf.VulnerabilityFinding: %w", err)
		}

		findings = append(findings, &vf.VulnerabilityFinding{
			ID:      uint64(row.ID),
			Finding: &finding,
		})
	}

	if len(findings) == 0 {
		return nil, store.ErrNoFindingsFound
	}

	return findings, nil
}

// Write writes new vulnerabilities in JSON format in the database.
func (m *manager) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	var createFindingsReq = sqlc.CreateFindingsParams{
		DetailsArray: make([][]byte, 0, len(findings)),
	}

	for _, finding := range findings {
		jsonFinding, err := protojson.Marshal(finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}
		createFindingsReq.InstanceIDArray = append(createFindingsReq.InstanceIDArray, m.newPgUUID(instanceID))
		createFindingsReq.DetailsArray = append(createFindingsReq.DetailsArray, jsonFinding)
	}

	if err := m.queries.CreateFindings(ctx, createFindingsReq); err != nil {
		return errors.Errorf("failed to write findings: %w", err)
	}

	return nil
}

// Update updates existing vulnerabilities in the underlying database.
func (m *manager) Update(ctx context.Context, instanceID uuid.UUID, findings []*vf.VulnerabilityFinding) error {
	tx, err := m.conn.Begin(ctx)
	if err != nil {
		return errors.Errorf("failed to begin update transaction: %w", err)
	}

	rollback := func(tx pgx.Tx, err error) error {
		if txErr := tx.Rollback(ctx); txErr != nil {
			return errors.Errorf("failed to rollback transaction for error %w: %w", err, txErr)
		}
		return errors.Errorf("rolledback transaction for error: %w", err)
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			// TODO: replace with logger.
			log.Printf("failed to rollback update transaction: %s", err.Error())
		}
	}()

	for _, finding := range findings {
		jsonFinding, err := protojson.Marshal(finding.Finding)
		if err != nil {
			return rollback(tx, errors.Errorf("could not json marshal finding: %w", err))
		}

		if err := m.queries.WithTx(tx).UpdateFinding(ctx, sqlc.UpdateFindingParams{
			InstanceID: m.newPgUUID(instanceID),
			ID:         int32(finding.ID),
			Details:    jsonFinding,
		}); err != nil {
			return rollback(
				tx,
				errors.Errorf(
					"could not update finding %d: %w",
					finding.ID,
					err,
				),
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return rollback(tx, errors.Errorf("failed to commit update transaction: %w", err))
	}

	return nil
}

// Close closes the connection to the underlying database.
func (m *manager) Close(ctx context.Context) error {
	if err := m.conn.Close(ctx); err != nil {
		return errors.Errorf("failed to close postgresql database: %w", err)
	}
	return nil
}

// Ping pings the connection to the underlying database.
func (m *manager) Ping(ctx context.Context) error {
	if err := m.conn.Ping(ctx); err != nil {
		return errors.Errorf("failed to ping postgresql database: %w", err)
	}
	return nil
}

func (m *manager) newPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}
