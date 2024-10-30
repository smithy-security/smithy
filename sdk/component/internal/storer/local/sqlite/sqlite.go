package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path"

	_ "github.com/mattn/go-sqlite3"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

const errInvalidConstructorEmptyReason = "cannot be empty"

type (
	manager struct {
		db     *sql.DB
		dbName string
	}

	// ErrInvalidConstructor should be used for invalid manager constructor errors.
	ErrInvalidConstructor struct {
		argName string
		reason  string
	}
)

func (e ErrInvalidConstructor) Error() string {
	return fmt.Sprintf("invalid argument '%s': %s", e.argName, e.reason)
}

// NewManager returns a new SQLite database manager.
func NewManager(dbPath string, dbName string) (*manager, error) {
	switch {
	case dbPath == "":
		return nil, ErrInvalidConstructor{
			argName: "db path",
			reason:  errInvalidConstructorEmptyReason,
		}
	case dbName == "":
		return nil, ErrInvalidConstructor{
			argName: "db name",
			reason:  errInvalidConstructorEmptyReason,
		}
	}

	db, err := sql.Open("sqlite3", path.Join(dbPath, dbName))
	if err != nil {
		return nil, fmt.Errorf("could not open sqlite db: %w", err)
	}

	return &manager{
		db:     db,
		dbName: dbName,
	}, nil
}

// TODO - implement me.
func (m *manager) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	return nil, nil
}

// TODO - implement me.
func (m *manager) Write(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

// TODO - implement me.
func (m *manager) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	return nil
}

// TODO - implement me.
func (m *manager) Close(ctx context.Context) error {
	if err := m.db.Close(); err != nil {
		return fmt.Errorf("could not close sqlite db: %w", err)
	}
	return nil
}
