package command

import (
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithyctl/internal/command/build"
	"github.com/smithy-security/smithyctl/internal/command/packaging"
	"github.com/smithy-security/smithyctl/internal/command/version"
	"github.com/smithy-security/smithyctl/internal/command/workflow"
)

// BuildComponentCommand exports the build command for external use.
func BuildComponentCommand() *cobra.Command {
	return build.NewCommand()
}

// PackageComponentCommand exports the package command for external use.
func PackageComponentCommand() *cobra.Command {
	return packaging.NewCommand()
}

// VersionCommand exports the version command for external use.
func VersionCommand() *cobra.Command {
	return version.NewCommand()
}

// WorkflowCommand exports the workflow command for external use.
func WorkflowCommand() *cobra.Command {
	return workflow.NewCommand()
}
