package component

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
)

var buildCmdFlags buildFlags

type (
	buildFlags struct{}
)

// NewBuildCommand returns a new build command.
func NewBuildCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Builds a component's container",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := buildComponent(cmd.Context(), buildCmdFlags); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}
}

func buildComponent(ctx context.Context, flags buildFlags) error {
	return nil
}
