package packaging

import (
	"github.com/spf13/cobra"
)

// NewCommand returns a new package command.
func NewCommand() *cobra.Command {
	// TODO: implement in https://linear.app/smithy/issue/OCU-473/package-components-using-oras
	return &cobra.Command{
		Use:   "package",
		Short: "Packages a component's configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
