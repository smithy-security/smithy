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

var revertCmdConfig = struct {
	targetMigration uint
}{}

var revertSubCmd = &cobra.Command{
	Use:     "revert",
	Short:   "Revert migrations applied to the database.",
	GroupID: "Migrations",
	RunE:    entrypointWrapper(revertMigrations),
}

func init() {
	revertSubCmd.Flags().UintVar(&revertCmdConfig.targetMigration, "target", 0, "Which migration to revert to.")
}

func revertMigrations(cmd *cobra.Command, args []string) error {
	if migrationsCmdConfig.migratiosnPath == "" {
		return fmt.Errorf("you need to provide a path to the migrations that will be applied")
	}
	slog.Info("reverting migrations", "migrations path:", migrationsCmdConfig.migratiosnPath)
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
	curVersion, isDirty, err := migrations.State(dirFS)
	if errors.Is(err, migrate.ErrNilVersion) {
		cmd.Println("no migrations applied to the database")
		return nil
	} else if err != nil {
		return fmt.Errorf("could not get state of database: %w", err)
	} else if isDirty {
		return fmt.Errorf("can't revert migrations of dirty DB. please fix first and then re-run")
	} else if revertCmdConfig.targetMigration >= curVersion {
		return fmt.Errorf("you need to provide a target migration version that is lower than the currently applied version (%d)", curVersion)
	}

	cmd.Println("Reverting migrations...")
	if err = migrations.Revert(dirFS, revertCmdConfig.targetMigration); err == nil {
		cmd.Println("Finished successfully reverting migrations")
	}
	return err
}
