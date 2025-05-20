package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/smithyctl/command/component"
	"github.com/smithy-security/smithy/smithyctl/command/version"
	"github.com/smithy-security/smithy/smithyctl/command/workflow"
	"github.com/smithy-security/smithy/smithyctl/internal/command"
)

func main() {
	err := command.
		NewRootCommand(
			version.NewCommand(),
			component.NewCommand(),
			workflow.NewCommand(),
		).
		Execute()

	if err != nil {
		errToUnwrap := err
		errPrintQueue := []string{}
		for errToUnwrap != nil {
			if _, canPrintStackTrace := errToUnwrap.(*errors.Error); canPrintStackTrace {
				errPrintQueue = append(errPrintQueue, string(errToUnwrap.(*errors.Error).Stack()))
			}

			errToUnwrap = errors.Unwrap(errToUnwrap)
		}

		if len(errPrintQueue) > 0 {
			_, printErr := fmt.Fprint(
				os.Stderr,
				"\nError stack trace is:\n\n",
				strings.Join(errPrintQueue, "\ncaused by:\n"),
				"\n",
			)

			if printErr != nil {
				panic(printErr.Error())
			}
		}

		os.Exit(1)
	}
}
