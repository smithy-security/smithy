package workflow

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/internal/command/workflow"
	"github.com/smithy-security/smithy/smithyctl/internal/engine"
	"github.com/smithy-security/smithy/smithyctl/internal/engine/docker"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

var runCmdFlags runFlags

type runFlags struct {
	specPath      string
	overridesPath string

	registryURL            string
	registryBaseRepository string
	registryAuthEnabled    bool
	registryAuthUsername   string

	registryAuthPassword string
	cleanRun             bool
}

// NewRunCommand returns a new run workflow command.
func NewRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Allows running workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runWorkflow(cmd.Context(), runCmdFlags); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}

	cmd.
		Flags().
		StringVar(
			&runCmdFlags.specPath,
			"spec-path",
			".",
			"the location of the workflow spec file",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.overridesPath,
			"overrides-path",
			"",
			"the location of the workflow overrides file",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.registryURL,
			"registry-url",
			"ghcr.io",
			"the reference to the OCI compliant registry",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.registryBaseRepository,
			"registry-base-repository",
			"smithy-security/manifests/components",
			"the repository where to push manifests to",
		)
	cmd.
		Flags().
		BoolVar(
			&runCmdFlags.registryAuthEnabled,
			"registry-auth-enabled",
			false,
			"if enabled, it requires authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.registryAuthUsername,
			"registry-auth-username",
			"",
			"the username used for authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.registryAuthPassword,
			"registry-auth-password",
			"",
			"the password used for authentication for the registry",
		)
	cmd.
		Flags().
		BoolVar(
			&runCmdFlags.cleanRun,
			"clean-run",
			false,
			"whether to clean up the local findings database or not post run",
		)

	return cmd
}

func runWorkflow(ctx context.Context, flags runFlags) error {
	reg, err := registry.New(
		flags.registryURL,
		flags.registryBaseRepository,
		flags.registryAuthEnabled,
		flags.registryAuthUsername,
		flags.registryAuthPassword,
	)
	if err != nil {
		return errors.Errorf("failed to initialize package registry: %w", err)
	}

	parser, err := workflow.NewSpecParser(reg, component.NewSpecParser())
	if err != nil {
		return errors.Errorf("failed to initialize workflow spec parser: %w", err)
	}

	wf, err := parser.Parse(ctx, flags.specPath, flags.overridesPath)
	if err != nil {
		return errors.Errorf("failed to parse workflow spec: %w", err)
	}

	dockerExec, err := docker.NewExecutor()
	if err != nil {
		return errors.Errorf("failed to initialize docker executor: %w", err)
	}

	executor, err := engine.NewExecutor(
		dockerExec,
		&engine.ExecutorConfig{
			CleanUpFindingsDB: flags.cleanRun,
		},
	)
	if err != nil {
		return errors.Errorf("failed to initialize executor: %w", err)
	}

	if err := executor.Execute(ctx, wf); err != nil {
		return errors.Errorf("unexpected workflow execution failure: %w", err)
	}

	return nil
}
