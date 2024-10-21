package main

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/smithy-security/smithy/cmd/smithyctl/components"
	"github.com/smithy-security/smithy/cmd/smithyctl/migrations"
	"github.com/smithy-security/smithy/cmd/smithyctl/pipelines"
)

var (
	rootCmd = &cobra.Command{
		Use:   "smithyctl",
		Short: "A CLI to manage all things related to Smithy",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initializeConfig(cmd)
		},
	}
	loggingFormat       string
	supportedLogFormats = []string{"text", "json"}
)

func main() {
	rootCmd.AddGroup(&cobra.Group{
		ID:    "top-level",
		Title: "Top-level Commands:",
	})
	pipelines.RegisterPipelinesSubcommands(rootCmd)
	migrations.RegisterMigrationsSubcommands(rootCmd)
	components.RegisterComponentsSubcommands(rootCmd)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{})))
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&loggingFormat, "log-format", "text", "The log format to use (supports 'text' for plain text and 'json' for JSON)")
}

func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()

	// When we bind flags to environment variables expect that the
	// environment variables are prefixed, e.g. a flag like --number
	// binds to an environment variable SMITHYCTL_NUMBER. This helps
	// avoid conflicts.
	v.SetEnvPrefix("smithyctl")

	// Environment variables can't have dashes in them, so bind them to their equivalent
	// keys with underscores, e.g. --favorite-color to SMITHYCTL_FAVORITE_COLOR
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Bind to environment variables
	// Works great for simple config names, but needs help for names
	// like --favorite-color which we fix in the visitall function
	v.AutomaticEnv()

	if !slices.Contains(supportedLogFormats, strings.ToLower(loggingFormat)) {
		return errors.Errorf("unsupported log format %s, supported formats are %s", loggingFormat, supportedLogFormats)
	} else if strings.ToLower(loggingFormat) == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})))
	}

	// Bind the current command's flags to viper
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				slog.Error(err.Error())
			}
		}
	})

	return nil
}
