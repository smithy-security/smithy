package components

import (
	"github.com/spf13/cobra"
)

var componentsCmd = &cobra.Command{
	Use:     "components",
	Short:   "A set of subcommands for building components",
	GroupID: "top-level",
}

func init() {
	componentsCmd.AddGroup(&cobra.Group{
		ID:    "Components",
		Title: "Component Commands:",
	})
}

// RegisterComponentsSubcommands add the subcomands of the package to the root
// command.
func RegisterComponentsSubcommands(rootCmd *cobra.Command) {
	componentsCmd.AddCommand(packageSubCmd)
	rootCmd.AddCommand(componentsCmd)
}
