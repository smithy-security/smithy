package workflow

import "github.com/spf13/cobra"

// NewCommand returns a new workflow command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Allows interacting with workflows",
		// TODO: implement in https://linear.app/smithy/issue/OCU-476/run-workflows-locally
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	return cmd
}
