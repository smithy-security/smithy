package workflow

import "github.com/spf13/cobra"

// NewCommand returns a new workflow command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Allows interacting with workflows",
	}

	cmd.AddCommand(NewRunCommand())

	return cmd
}
