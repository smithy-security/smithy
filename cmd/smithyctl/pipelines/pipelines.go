package pipelines

import (
	"github.com/spf13/cobra"
)

var pipelinesCmd = &cobra.Command{
	Use:     "pipelines",
	Short:   "A set of subcommands for building pipelines",
	GroupID: "top-level",
}

func init() {
	pipelinesCmd.AddGroup(&cobra.Group{
		ID:    "Pipelines",
		Title: "Pipeline Commands:",
	})
}

func RegisterPipelinesSubcommands(rootCmd *cobra.Command) {
	pipelinesCmd.AddCommand(deploySubCmd)
	rootCmd.AddCommand(pipelinesCmd)
}
