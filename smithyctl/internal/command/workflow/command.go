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
	cmd.AddCommand(runWorkflowCommand())
	return cmd
}

// runWorkflowCommand defines the run sub-command.
func runWorkflowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Runs a workflow",
		// TODO: implement in https://linear.app/smithy/issue/OCU-476/run-workflows-locally
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
