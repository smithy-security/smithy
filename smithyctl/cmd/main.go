package main

import (
	"log"

	"github.com/smithy-security/smithyctl/internal/command"
	"github.com/smithy-security/smithyctl/internal/command/build"
	"github.com/smithy-security/smithyctl/internal/command/packaging"
	"github.com/smithy-security/smithyctl/internal/command/version"
	"github.com/smithy-security/smithyctl/internal/command/workflow"
)

func main() {
	if err := command.
		NewRootCommand(
			version.NewCommand(),
			build.NewCommand(),
			packaging.NewCommand(),
			workflow.NewCommand(),
		).
		Execute(); err != nil {
		log.Fatalf("could not execute smithyctl: %w", err)
	}
}
