package main

import (
	"database/sql"
	"fmt"
)

func migrate() error {
	db, err := sql.Open("sqlite3", "smithy.db")
	if err != nil {
		return fmt.Errorf("could not open sqlite db: %w", err)
	}

	stmt, err := db.Prepare(`
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
