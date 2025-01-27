package main

import (
	"log"

	"github.com/smithy-security/smithyctl/command/component"
	"github.com/smithy-security/smithyctl/command/version"
	"github.com/smithy-security/smithyctl/command/workflow"
	"github.com/smithy-security/smithyctl/internal/command"
)

func main() {
	if err := command.
		NewRootCommand(
			version.NewCommand(),
			component.NewCommand(),
			workflow.NewCommand(),
		).
		Execute(); err != nil {
		log.Fatalf("could not execute smithyctl: %v", err)
	}
}
