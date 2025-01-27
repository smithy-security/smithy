package db

import (
	"io/fs"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	bindata "github.com/golang-migrate/migrate/v4/source/go_bindata"
)

type Migrations struct {
	*DB
	*PGUrl

	MigrationsTable string
}

func (m *Migrations) ListAvailable(migrationsDir fs.FS) (*bindata.AssetSource, error) {
	var assetNames []string
	if _, err := fs.Stat(migrationsDir, "."); err != nil {
		return nil, errors.Errorf("could not find migrations directory: %w", err)
	}
	if err := fs.WalkDir(migrationsDir, ".", func(path string, info fs.DirEntry, err error) error {
		if !info.IsDir() {
			assetNames = append(assetNames, info.Name())
		}
		return nil
	}); err != nil {
		return nil, errors.Errorf("could not walk migrations directory: %w", err)
	}

	return bindata.Resource(
		assetNames,
		func(name string) ([]byte, error) {
			return fs.ReadFile(migrationsDir, filepath.Join(".", name))
		},
	), nil
}

func (m *Migrations) driver(migrationsDir fs.FS) (*migrate.Migrate, error) {
	driver, err := m.WithInstance(&postgres.Config{
		MigrationsTable: m.MigrationsTable,
		SchemaName:      m.SchemaSearchPath(),
	})
	if err != nil {
		return nil, errors.Errorf("could not initialise DB driver: %w", err)
	}

	resources, err := m.ListAvailable(migrationsDir)
	if err != nil {
		return nil, err
	}

	if len(resources.Names) == 0 {
		return nil, errors.New("no migrations found")
	}

	resourcesDriver, err := bindata.WithInstance(resources)
	if err != nil {
		return nil, errors.Errorf("could not create migration bindata instance: %w", err)
	}

	return migrate.NewWithInstance("go-bindata", resourcesDriver, "smithy", driver)
}

func (m *Migrations) State(migrationsDir fs.FS) (uint, bool, error) {
	migrationDriver, err := m.driver(migrationsDir)
	if err != nil {
		return 0, false, err
	}

	return migrationDriver.Version()
}

func (m *Migrations) Apply(migrationsDir fs.FS) error {
	migrationDriver, err := m.driver(migrationsDir)
	if err != nil {
		return err
	}

	_, isDBDirty, err := migrationDriver.Version()
	if isDBDirty {
		return errors.New("some migrations failed and DB is dirty. will not proceed with migrations")
	} else if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return errors.Errorf("error getting migration version: %w", err)
	}

	if err = migrationDriver.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return errors.Errorf("could not migrate DB: %w", err)
	}

	return nil
}

func (m *Migrations) Revert(migrationsDir fs.FS, toVersion uint) error {
	migrationDriver, err := m.driver(migrationsDir)
	if err != nil {
		return err
	}

	dbVersion, isDBDirty, err := migrationDriver.Version()
	if isDBDirty {
		return errors.New("some migrations failed and DB is dirty. will not proceed with migrations")
	} else if errors.Is(err, migrate.ErrNilVersion) {
		return errors.New("no migrations have been applied so nothing to revert")
	} else if err != nil {
		return errors.Errorf("error getting migration version: %w", err)
	}

	if err = migrationDriver.Steps(int(toVersion) - int(dbVersion)); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return errors.Errorf("could not revert migrations DB: %w", err)
	}

	return nil
}
