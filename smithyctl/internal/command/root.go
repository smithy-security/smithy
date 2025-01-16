package command

import (
	"github.com/spf13/cobra"
)

// NewRootCommand register all the subcommands into the same root command.
func NewRootCommand(commands ...*cobra.Command) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "smithyctl",
		Short: "A CLI app for managing components and workflows",
	}

	for _, cmd := range commands {
		rootCmd.AddCommand(cmd)
	}

	return rootCmd
}
