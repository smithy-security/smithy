package component

import "github.com/spf13/cobra"

// NewBuildCommand returns a new build command.
func NewBuildCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Builds a component's container",
		// TODO: implement in https://linear.app/smithy/issue/OCU-471/build-components
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
