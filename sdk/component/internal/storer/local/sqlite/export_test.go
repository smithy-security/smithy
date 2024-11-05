package sqlite

import "github.com/go-errors/errors"

// CreateTable is used to create a table in testing settings.
func (m *manager) CreateTable() error {
	stmt, err := m.db.Prepare(`
		CREATE TABLE finding (
			id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
			instance_id UUID NOT NULL UNIQUE,
			findings TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return errors.Errorf("could not prepare statement for creating table: %w", err)
	}

	if _, err := stmt.Exec(); err != nil {
		return errors.Errorf("could not create table: %w", err)
	}

	return stmt.Close()
}
