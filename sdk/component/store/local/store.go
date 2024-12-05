package localstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
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
		if clock == nil {
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
func (m *manager) Read(ctx context.Context, instanceID uuid.UUID) ([]*ocsf.VulnerabilityFinding, error) {
	stmt, err := m.db.PrepareContext(ctx, `
		SELECT (findings) 
			FROM finding 
			WHERE instance_id = :instance_id
		;
	`)
	if err != nil {
		return nil, errors.Errorf("could not prepare select statement: %w", err)
	}

	defer stmt.Close()

	var jsonFindingsStr string
	err = stmt.
		QueryRowContext(
			ctx,
			sql.Named(LocalStoreColumnNameInstanceId.String(), instanceID.String()),
		).
		Scan(&jsonFindingsStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.Errorf("%s: %w", instanceID.String(), store.ErrNoFindingsFound)
		}
		return nil, errors.Errorf("could not select findings: %w", err)
	}

	var jsonFindings []json.RawMessage
	if err := json.Unmarshal([]byte(jsonFindingsStr), &jsonFindings); err != nil {
		return nil, errors.Errorf("could not unmarshal json findings to []json.RawMessage: %w", err)
	}

	var findings []*ocsf.VulnerabilityFinding
	for _, jsonFinding := range jsonFindings {
		var finding ocsf.VulnerabilityFinding
		if err := protojson.Unmarshal(jsonFinding, &finding); err != nil {
			return nil, errors.Errorf("failed to unmarshal JSON findings to *ocsf.VulnerabilityFinding: %w", err)
		}
		findings = append(findings, &finding)
	}

	return findings, nil
}

// Write writes new vulnerabilities in JSON format in the database.
func (m *manager) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	jsonFindings, err := m.marshalFindings(findings)
	if err != nil {
		return err
	}

	stmt, err := m.db.PrepareContext(ctx, `
		INSERT INTO finding (instance_id, findings) 
			VALUES (:instance_id, :findings)
		;
	`)
	if err != nil {
		return errors.Errorf("could not prepare write statement: %w", err)
	}

	defer stmt.Close()

	if _, err = stmt.Exec(
		sql.Named(LocalStoreColumnNameInstanceId.String(), instanceID.String()),
		sql.Named(LocalStoreColumnNameFindings.String(), jsonFindings),
	); err != nil {
		return errors.Errorf("could not insert findings: %w", err)
	}

	return nil
}

// Update updates existing vulnerabilities in the underlying database.
// It returns ErrNoFindingsFound if the passed instanceID is not found.
func (m *manager) Update(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	jsonFindings, err := m.marshalFindings(findings)
	if err != nil {
		return err
	}

	stmt, err := m.db.PrepareContext(ctx, `
		UPDATE finding 
			SET 
			    findings = :findings,
			    updated_at = :updated_at
			WHERE 
			    instance_id = :instance_id
		;
	`)
	if err != nil {
		return errors.Errorf("could not prepare update statement: %w", err)
	}

	defer stmt.Close()

	res, err := stmt.Exec(
		sql.Named(LocalStoreColumnNameInstanceId.String(), instanceID.String()),
		sql.Named(LocalStoreColumnNameUpdatedAt.String(), m.clock.Now().UTC().Format(time.RFC3339)),
		sql.Named(LocalStoreColumnNameFindings.String(), jsonFindings),
	)
	if err != nil {
		return errors.Errorf("could not update findings: %w", err)
	}

	r, err := res.RowsAffected()
	switch {
	case err != nil:
		return errors.Errorf("could not get rows affected: %w", err)
	case r <= 0:
		return errors.Errorf(
			"could not update findings for instance '%s': %w",
			instanceID.String(),
			store.ErrNoFindingsFound,
		)
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
			instance_id UUID NOT NULL UNIQUE,
			findings TEXT NOT NULL,
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

func (m *manager) marshalFindings(findings []*ocsf.VulnerabilityFinding) (string, error) {
	var rawFindings []json.RawMessage
	for _, finding := range findings {
		b, err := protojson.Marshal(finding)
		if err != nil {
			return "", errors.Errorf("could not json marshal finding: %w", err)
		}
		rawFindings = append(rawFindings, b)
	}

	jsonFindings, err := json.Marshal(rawFindings)
	if err != nil {
		return "", errors.Errorf("could not json marshal findings: %w", err)
	}

	return string(jsonFindings), nil
}
