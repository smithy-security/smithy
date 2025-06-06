package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/sqlclient"
	_ "ariga.io/atlas/sql/sqlite"
	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smithy-security/pkg/utils"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/store/local/sqlite/sqlc"
	_ "github.com/smithy-security/smithy/sdk/component/store/local/sqlite/sqlc/migrations"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	manager struct {
		clock   clockwork.Clock
		dsn     string
		db      *sql.DB
		queries *sqlc.Queries
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
func NewManager(ctx context.Context, opts ...managerOption) (*manager, error) {
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
		if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(mgr.dsn), 0755); err != nil {
				return nil, errors.Errorf("could not create directory: %w", err)
			}
			f, err := os.Create(mgr.dsn)
			if err != nil {
				return nil, errors.Errorf("could not create sqlite db file: %w", err)
			}
			_ = f.Close()
		} else {
			return nil, errors.Errorf("unexpected stat error: %w", err)
		}
	}

	mgr.db, err = sql.Open("sqlite3", mgr.dsn)
	if err != nil {
		return nil, errors.Errorf("could not open sqlite db: %w", err)
	}

	mgr.queries = sqlc.New(mgr.db)

	if err := mgr.migrate(ctx); err != nil {
		return nil, errors.Errorf("could not migrate: %w", err)
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
	rawFindings, err := m.queries.FindingsByID(ctx, instanceID.String())
	if err != nil {
		return nil, errors.Errorf("could not find findings: %w", err)
	}

	var findings = make([]*vf.VulnerabilityFinding, 0, len(rawFindings))
	for _, finding := range rawFindings {
		var ocsfFinding ocsf.VulnerabilityFinding
		if err := protojson.Unmarshal([]byte(finding.Details), &ocsfFinding); err != nil {
			return nil, errors.Errorf("could not unmarshal finding: %w", err)
		}

		findings = append(findings, &vf.VulnerabilityFinding{
			ID:      uint64(finding.ID),
			Finding: &ocsfFinding,
		})
	}

	if len(findings) == 0 {
		return nil, store.ErrNoFindingsFound
	}

	return findings, nil
}

// Write writes new vulnerabilities in JSON format in the database.
func (m *manager) Write(ctx context.Context, instanceID uuid.UUID, findings []*ocsf.VulnerabilityFinding) error {
	tx, err := m.db.Begin()
	if err != nil {
		return errors.Errorf("could not begin write transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("could not rollback transaction: %v", err)
		}
	}()

	rollback := func(tx *sql.Tx, err error) error {
		if txErr := tx.Rollback(); txErr != nil {
			return errors.Errorf("could not rollback transaction for error %w: %w", err, txErr)
		}
		return errors.Errorf("unexpected write error, rolled back: %w", err)
	}

	for _, finding := range findings {
		b, err := protojson.Marshal(finding)
		if err != nil {
			return rollback(tx, errors.Errorf("could not marshal finding: %w", err))
		}

		if err := m.queries.WithTx(tx).CreateFinding(
			ctx,
			sqlc.CreateFindingParams{
				InstanceID: instanceID.String(),
				Details:    string(b),
			},
		); err != nil {
			return rollback(tx, errors.Errorf("could not create finding: %w", err))
		}
	}

	if err := tx.Commit(); err != nil {
		return rollback(tx, errors.Errorf("could not commit write transaction: %w", err))
	}

	return nil
}

// Update updates existing vulnerabilities in the underlying database.
func (m *manager) Update(ctx context.Context, instanceID uuid.UUID, findings []*vf.VulnerabilityFinding) error {
	tx, err := m.db.Begin()
	if err != nil {
		return errors.Errorf("could not begin update transaction: %w", err)
	}

	rollback := func(tx *sql.Tx, err error) error {
		if txErr := tx.Rollback(); txErr != nil {
			return errors.Errorf("could not rollback transaction for error %w: %w", err, txErr)
		}
		return errors.Errorf("unexpected update error, rolled back: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("could not rollback transaction: %v", err)
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

		if _, err := m.queries.WithTx(tx).UpdateFinding(ctx, sqlc.UpdateFindingParams{
			InstanceID: instanceID.String(),
			Details:    string(b),
			ID:         int64(finding.ID),
		}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return rollback(
					tx,
					errors.Errorf("no finding found for id %d: %w", finding.ID, store.ErrNoFindingsFound),
				)
			}
			return rollback(tx, errors.Errorf("could not update finding: %w", err))
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
	return nil
}

// RemoveDatabase removes the underlying sqlite database file.
func (m *manager) RemoveDatabase() error {
	return os.RemoveAll(m.dsn)
}

//go:embed sqlc/migrations/*
var migrationsFS embed.FS

func (m *manager) migrate(ctx context.Context) error {
	client, err := sqlclient.Open(ctx, fmt.Sprintf("sqlite://%s", m.dsn))
	if err != nil {
		return errors.Errorf("could not open sqlite db: %w", err)
	}
	defer client.Close()

	// This is done so that we can find the migrations even when the SDK is vendored.
	dir, err := loadEmbeddedMigrations(migrationsFS, "sqlc/migrations")
	if err != nil {
		return errors.Errorf("could not open migrations directory: %w", err)
	}

	executor, err := migrate.NewExecutor(
		client.Driver,
		dir,
		migrate.NopRevisionReadWriter{},
		migrate.WithAllowDirty(true),
	)
	if err != nil {
		return errors.Errorf("could not create migration executor: %w", err)
	}

	if err := executor.ValidateDir(ctx); err != nil {
		return errors.Errorf("could not validate migration directory: %w", err)
	}

	const allPendingMigrations = -1
	if err := executor.ExecuteN(ctx, allPendingMigrations); err != nil {
		return errors.Errorf("could not execute migrations: %w", err)
	}

	return nil
}

// loadEmbeddedMigrations reads embedded files into a *migrate.MemDir
func loadEmbeddedMigrations(migrationsFS embed.FS, dirPrefix string) (*migrate.MemDir, error) {
	memDir := &migrate.MemDir{}

	err := fs.WalkDir(migrationsFS, dirPrefix, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			// Read the file contents
			data, err := migrationsFS.ReadFile(path)
			if err != nil {
				return err
			}

			// Add the file to the in-memory directory
			relPath := path[len(dirPrefix)+1:] // Strip the directory prefix
			if err := memDir.WriteFile(relPath, data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	memDir.SetPath("sqlc/migrations")
	return memDir, nil
}
