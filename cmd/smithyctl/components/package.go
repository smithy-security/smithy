package components

import (
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/pkg/components"
)

var packageSubCmdFlags struct {
	outfile      string
	version      string
	chartVersion string
	name         string
}

var packageSubCmd = &cobra.Command{
	Use:     "package",
	Short:   `Package all the Tasks in the components folder into a Helm package.`,
	GroupID: "Components",
	RunE:    packageComponents,
}

func init() {
	packageSubCmd.Flags().StringVarP(&packageSubCmdFlags.version, "version", "v", "", "The version of the components in the Helm package")
	packageSubCmd.Flags().StringVar(&packageSubCmdFlags.chartVersion, "chart-version", "0.1.0", "The version of the components in the Helm package")
	packageSubCmd.Flags().StringVarP(&packageSubCmdFlags.name, "name", "n", "", "The name of the Helm package")
}

func packageComponents(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.Errorf("you need to provide a path to a components folder")
	}

	return components.Package(cmd.Context(), packageSubCmdFlags.name, args[0], packageSubCmdFlags.version, packageSubCmdFlags.chartVersion)
}
