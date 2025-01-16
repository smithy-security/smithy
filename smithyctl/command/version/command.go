package version

import "github.com/spf13/cobra"

// NewCommand returns a new version command.
func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Outputs smithyctl's version",
		// TODO: implement in https://linear.app/smithy/issue/OCU-481/version-command
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
