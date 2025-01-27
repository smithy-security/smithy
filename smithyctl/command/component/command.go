package component

import "github.com/spf13/cobra"

// NewCommand returns a new component command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Allows to interact with components",
	}

	cmd.AddCommand(NewBuildCommand())
	cmd.AddCommand(NewPackageCommand())
	cmd.AddCommand(NewRunCommand())

	return cmd
}
