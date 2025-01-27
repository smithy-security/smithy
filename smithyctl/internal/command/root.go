package command

import (
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithyctl/internal/logging"
)

var flags rootFlags

type rootFlags struct {
	debugEnabled bool
	debugLevel   string
}

// NewRootCommand register all the subcommands into the same root command.
func NewRootCommand(commands ...*cobra.Command) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "smithyctl",
		Short: "A CLI app for managing components and workflows",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flags.debugEnabled {
				cmd.SetContext(logging.ContextWithLogger(
					cmd.Context(),
					logging.NewDefaultLogger(flags.debugLevel),
				))
			}
			return nil
		},
	}

	rootCmd.
		PersistentFlags().
		BoolVar(
			&flags.debugEnabled,
			"debug-enabled",
			false,
			"enabled debug logs",
		)
	rootCmd.
		PersistentFlags().
		StringVar(
			&flags.debugLevel,
			"debug-level",
			"debug",
			"sets the debug level",
		)

	for _, cmd := range commands {
		rootCmd.AddCommand(cmd)
	}

	return rootCmd
}
