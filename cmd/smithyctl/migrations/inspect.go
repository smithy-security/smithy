package migrations

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-errors/errors"
	"github.com/golang-migrate/migrate/v4"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/pkg/db"
)

var inspectSubCmd = &cobra.Command{
	Use:     "inspect",
	Short:   "Check which migrations have been applied to the database.",
	GroupID: "Migrations",
	RunE:    entrypointWrapper(inspectMigrations),
}

var migrationsInspectCmdConfig = struct {
	jsonOutput bool
}{}

func init() {
	migrationsCmd.PersistentFlags().BoolVar(&migrationsInspectCmdConfig.jsonOutput, "json", false, "Output inspection data in json")
}

func inspectMigrations(cmd *cobra.Command, args []string) error {
	if migrationsCmdConfig.migratiosnPath == "" {
		return errors.Errorf("you need to provide a path to the migrations that will be applied")
	}
	slog.Info("inspecting migrations", "migrations path:", migrationsCmdConfig.migratiosnPath)
	dirFS := os.DirFS(migrationsCmdConfig.migratiosnPath)

	dbURL, err := db.ParseConnectionStr(migrationsCmdConfig.connStr)
	if err != nil {
		return errors.Errorf("could not parse connection string: %w", err)
	}

	dbConn, err := dbURL.Connect()
	if err != nil {
		return errors.Errorf("could not connect to the database: %w", err)
	}

	migrations := db.Migrations{DB: dbConn, PGUrl: dbURL, MigrationsTable: migrationsCmdConfig.migrationsTable}
	latestMigration, isDirty, err := migrations.State(dirFS)
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return errors.Errorf("could not get state of database: %w", err)
	}

	if migrationsInspectCmdConfig.jsonOutput {
		jsonOutput := struct {
			Version uint
			Dirty   bool
		}{latestMigration, isDirty}

		var marshaledBytes []byte
		marshaledBytes, err = json.Marshal(jsonOutput)
		if err != nil {
			return errors.Errorf("could not marshal JSON output: %w", err)
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(marshaledBytes))
	} else {
		table := tablewriter.NewWriter(cmd.OutOrStdout())
		table.SetHeader([]string{"", ""})
		table.Append([]string{"Latest Migration Version", fmt.Sprintf("%d", latestMigration)})
		table.Append([]string{"Has Failed Migrations", fmt.Sprintf("%v", isDirty)})
		table.Render()
	}

	return err
}
