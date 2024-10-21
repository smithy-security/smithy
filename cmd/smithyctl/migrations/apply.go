package migrations

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/pkg/db"
)

var applySubCmd = &cobra.Command{
	Use:     "apply",
	Short:   "Apply migrations to the database.",
	GroupID: "Migrations",
	RunE:    entrypointWrapper(applyMigrations),
	Example: `1.Run the command as a K8s Job in your local dev environment:

$ smithyctl migrations apply --url "postgres://postgres:postgres@postgres.smithy.svc.cluster.local:5432/?sslmode=disable" \
						   --as-k8s-job \
						   --namespace smithy

If you can directly access the database then you can apply migrations as follows:

$ smithyctl migrations apply --url "postgres://postgres:postgres@localhost:5432/?sslmode=disable" --migrations-path ./pkg/enrichment
or
$ SMITHYCTL_MIGRATIONS_PATH=./pkg/enrichment smithyctl migrations apply --url "postgres://postgres:postgres@localhost:5432/?sslmode=disable"
`,
}

func applyMigrations(cmd *cobra.Command, args []string) error {
	if migrationsCmdConfig.migratiosnPath == "" {
		return fmt.Errorf("you need to provide a path to the migrations that will be applied")
	}
	slog.Info("applying migrations", "migrations path:", migrationsCmdConfig.migratiosnPath)

	dirFS := os.DirFS(migrationsCmdConfig.migratiosnPath)

	dbURL, err := db.ParseConnectionStr(migrationsCmdConfig.connStr)
	if err != nil {
		return fmt.Errorf("could not parse connection string: %w", err)
	}

	dbConn, err := dbURL.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to the database: %w", err)
	}

	migrations := db.Migrations{DB: dbConn, PGUrl: dbURL, MigrationsTable: migrationsCmdConfig.migrationsTable}
	_, isDirty, err := migrations.State(dirFS)
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("could not get state of database: %w", err)
	} else if isDirty {
		return fmt.Errorf("can't apply migrations to dirty DB. please fix first and then re-run")
	}

	cmd.Println("Applying migrations...")
	if err = migrations.Apply(dirFS); err == nil {
		cmd.Println("Finished successfully applying migrations")
	}
	return err
}
