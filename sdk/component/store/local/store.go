package localstore

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component/internal/utils"
	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	manager struct {
		clock clockwork.Clock
		dsn   string
		db    *sql.DB
	}

	managerOption func(*manager) error

	// ErrInvalidConstructor should be used for invalid manager constructor errors.
	ErrInvalidConstructor struct {
		argName string
		reason  string
	}
)

// ManagerWithClock allows customising manager's clock.
func ManagerWithClock(clock clockwork.Clock) managerOption {
	return func(m *manager) error {
		if utils.IsNil(clock) {
			return errors.New("invalid nil clock")
		}
		m.clock = clock
		return nil
	}
}

func (e ErrInvalidConstructor) Error() string {
	return fmt.Sprintf("invalid argument '%s': %s", e.argName, e.reason)
}

// NewManager returns a new SQLite database manager.
func NewManager(opts ...managerOption) (*manager, error) {
	var (
		mgr = &manager{
			clock: clockwork.NewRealClock(),
			dsn:   "smithy.db",
		}
		err error
	)

	for _, opt := range opts {
		if err := opt(mgr); err != nil {
			return nil, errors.Errorf("could not apply option: %w", err)
		}
	}

	// Create sqlite database file if not exists.
	if _, err := os.Stat(mgr.dsn); err != nil {
		if !os.IsNotExist(err) {
			f, err := os.Create(mgr.dsn)
			if err != nil {
				return nil, errors.Errorf("could not create sqlite db: %w", err)
			}
			_ = f.Close()
		}
	}

	mgr.db, err = sql.Open("sqlite3", mgr.dsn)
	if err != nil {
		return nil, errors.Errorf("could not open sqlite db: %w", err)
	}

	if err := mgr.migrate(); err != nil {
		return nil, errors.Errorf("could not apply migrations: %w", err)
	}

	return mgr, nil
}

// Validate validates the passed finding.
// TODO: to be tackled with https://linear.app/smithy/issue/OCU-259/validate-component-input-and-output.
func (m *manager) Validate(*ocsf.VulnerabilityFinding) error {
	return nil
}

// Read finds Vulnerability Findings by instanceID.
// It returns ErrNoFindingsFound is not vulnerabilities were found.
func (m *manager) Read(ctx context.Context, instanceID uuid.UUID) ([]*vf.VulnerabilityFinding, error) {
	stmt, err := m.db.PrepareContext(ctx, `
		SELECT id, details
			FROM finding 
			WHERE instance_id = :instance_id
		;
	`)
	if err != nil {
		return nil, errors.Errorf("could not prepare select statement: %w", err)
	}

	defer stmt.Close()

	rows, err := stmt.
		QueryContext(
			ctx,
			sql.Named(LocalStoreColumnNameInstanceId.String(), instanceID.String()),
		)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.Errorf("%s: %w", instanceID.String(), store.ErrNoFindingsFound)
		}
		return nil, errors.Errorf("could not select findings: %w", err)
	}

	var findings []*vf.VulnerabilityFinding
	for rows.Next() {
		var (
			findingID          uint64
			jsonFindingDetails string
		)

		if err := rows.Scan(&findingID, &jsonFindingDetails); err != nil {
			return nil, errors.Errorf("could not scan row: %w", err)
		}

		var finding ocsf.VulnerabilityFinding
		if err := protojson.Unmarshal([]byte(jsonFindingDetails), &finding); err != nil {
			return nil, errors.Errorf(
				"failed to unmarshal JSON findings to *ocsf.VulnerabilityFinding for id %d: %w",
				findingID,
				err,
			)
		}

		findings = append(findings, &vf.VulnerabilityFinding{
			ID:      findingID,
			Finding: &finding,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Errorf("could not scan rows: %w", err)
	}

	if len(findings) == 0 {
		return nil, store.ErrNoFindingsFound
	}

	return findings, nil
}

// Write writes new vulnerabilities in JSON format in the database.
func (m *manager) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	var (
		placeHolders strings.Builder
		values       []any
	)

	for i, finding := range findings {
		placeHolders.WriteString("(?, ?)")
		if i != len(findings)-1 {
			placeHolders.WriteString(",")
		}

		b, err := protojson.Marshal(finding)
		if err != nil {
			return errors.Errorf("could not marshal JSON finding: %w", err)
		}

		values = append(values, instanceID.String(), string(b))
	}

	query := fmt.Sprintf("INSERT INTO finding (instance_id, details) VALUES %s;", placeHolders.String())
	stmt, err := m.db.PrepareContext(ctx, query)
	if err != nil {
		return errors.Errorf("could not prepare write statement: %w", err)
	}

	defer stmt.Close()

	if _, err = stmt.Exec(values...); err != nil {
		return errors.Errorf("could not insert findings: %w", err)
	}

	return nil
}

// Update updates existing vulnerabilities in the underlying database.
// It returns ErrNoFindingsFound if the passed instanceID is not found.
func (m *manager) Update(ctx context.Context, instanceID uuid.UUID, findings []*vf.VulnerabilityFinding) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Errorf("could not start update transaction: %w", err)
	}

	rollback := func(tx *sql.Tx, err error) error {
		if txErr := tx.Rollback(); txErr != nil {
			return errors.Errorf("could not rollback transaction for error %w: %w", err, txErr)
		}
		return errors.Errorf("unexpected update error, rolled back: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil {
			// TODO: replace with logger.
			log.Printf("failed to rollback update transaction: %s", err)
		}
	}()

	for _, finding := range findings {
		b, err := protojson.Marshal(finding.Finding)
		if err != nil {
			return rollback(
				tx,
				errors.Errorf("could not marshal JSON finding: %w", err),
			)
		}

		stmt, err := tx.PrepareContext(ctx, `
		UPDATE finding 
			SET 
			    details = :details,
			    updated_at = :updated_at
			WHERE
			    id = :id AND
			    instance_id = :instance_id
		;
		`)
		if err != nil {
			return rollback(
				tx,
				errors.Errorf("could not prepare update statement: %w", err),
			)
		}

		res, err := stmt.Exec(
			sql.Named(LocalStoreColumnNameInstanceId.String(), instanceID.String()),
			sql.Named(LocalStoreColumnNameUpdatedAt.String(), m.clock.Now().UTC().Format(time.RFC3339)),
			sql.Named(LocalStoreColumnNameDetails.String(), string(b)),
			sql.Named(LocalStoreColumnNameId.String(), finding.ID),
		)
		if err != nil {
			_ = stmt.Close()
			return rollback(
				tx,
				errors.Errorf("could not update findings: %w", err),
			)
		}

		_ = stmt.Close()
		r, err := res.RowsAffected()
		switch {
		case err != nil:
			return rollback(
				tx,
				errors.Errorf(
					"could not get rows affected for finding with id %d: %w", finding.ID, err),
			)
		case r <= 0:
			return rollback(
				tx,
				errors.Errorf(
					"could not update findings for instance '%s' with id %d: %w",
					instanceID.String(),
					finding.ID,
					store.ErrNoFindingsFound,
				),
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return rollback(tx, errors.Errorf("could not commit update transaction: %w", err))
	}

	return nil
}

// Close closes the connection to the underlying database.
func (m *manager) Close(ctx context.Context) error {
	if err := m.db.Close(); err != nil {
		return errors.Errorf("could not close sqlite db: %w", err)
	}
	if err := os.Remove(m.dsn); err != nil {
		return errors.Errorf("could not remove sqlite db file: %w", err)
	}
	return nil
}

// TODO: potentially leverage migrations here but this is simple enough for now for local setup.
// Tracked here https://linear.app/smithy/issue/OCU-274/automigrate-on-sqlite-storage.
func (m *manager) migrate() error {
	stmt, err := m.db.Prepare(`
		CREATE TABLE IF NOT EXISTS finding (
			id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
			instance_id UUID NOT NULL,
			details TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("could not prepare statement for creating table: %w", err)
	}

	if _, err := stmt.Exec(); err != nil {
		return fmt.Errorf("could not create table: %w", err)
	}

	return stmt.Close()
}
