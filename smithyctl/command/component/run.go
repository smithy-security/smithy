package component

import "github.com/spf13/cobra"

// NewRunCommand returns a new run command.
func NewRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Builds a component's container",
		// TODO: implement in https://linear.app/smithy/issue/OCU-476/run-workflows-locally
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
