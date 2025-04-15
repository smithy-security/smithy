package version

import (
	"log"

	"github.com/spf13/cobra"
)

// SmithyCTLVersion overridable smithyctl version.
var SmithyCTLVersion = "development"

// NewCommand returns a new version command.
func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Outputs smithyctl's version",
		RunE: func(_ *cobra.Command, _ []string) error {
			log.Println(SmithyCTLVersion)
			return nil
		},
	}
}
