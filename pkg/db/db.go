package db

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type DB struct {
	*sqlx.DB
	*PGUrl
}

type PGUrl struct {
	*url.URL
}

func ParseConnectionStr(connStr string) (*PGUrl, error) {
	parsedURL, err := url.Parse(connStr)
	if err != nil {
		return nil, err
	} else if parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql" {
		return nil, errors.New("currently Smithy only supports postgres or other databases that use the same frontend")
	}

	if search_paths, found := parsedURL.Query()["search_path"]; found && len(search_paths) > 1 {
		return nil, errors.New("multiple search paths defined in the connection string")
	}

	return &PGUrl{parsedURL}, nil
}

// SchemaSearchPath extracts the schema search path component from a
// PostgreSQL connection URL; if no search path is specified, the empty string
// is returned.
func (pgUrl *PGUrl) SchemaSearchPath() string {
	if path, found := pgUrl.Query()["search_path"]; found && len(path) == 1 {
		return path[0]
	}

	return ""
}

func (pgUrl *PGUrl) HasPassword() bool {
	if pgUrl.User == nil {
		return false
	}
	_, hasPass := pgUrl.User.Password()
	return hasPass
}

func (pgUrl *PGUrl) Connect() (*DB, error) {
	connectionString, err := pq.ParseURL(pgUrl.String())
	if err != nil {
		return nil, fmt.Errorf("could not parse URL into connection string: %w", err)
	}

	sqlxDB, err := sqlx.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return &DB{sqlxDB, pgUrl}, nil
}

func (db *DB) MustHaveSchema() {
	if err := db.EnsureHasSchema(); err != nil {
		panic(err)
	}
}

func (db *DB) EnsureHasSchema() error {
	searchPath := db.SchemaSearchPath()
	_, err := db.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, pq.QuoteIdentifier(searchPath)))
	if err != nil {
		return fmt.Errorf("could not create schema: %w", err)
	}

	return nil
}

func (db *DB) WithInstance(config *postgres.Config) (database.Driver, error) {
	return postgres.WithInstance(db.DB.DB, config)
}

// TODO: decide if this is ever used
// // getSchemaSearchPathFromKV extracts the schema search path component from a
// // PostgreSQL keyword/value connection string; if no search path is specified,
// // the empty string is returned.
// func getSchemaSearchPathFromKV(kvStr string) (string, error) {
// 	var path string

// 	for _, pair := range strings.Fields(kvStr) {
// 		elems := strings.SplitN(pair, "=", 2)
// 		if elems[0] == "search_path" {
// 			if path != "" {
// 				return "", errors.New("multiple search_paths defined in database connection DSN")
// 			}

// 			path = elems[1]
// 		}
// 	}

// 	return path, nil
// }
