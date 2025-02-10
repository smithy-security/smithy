package component

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

var packageCmdFlags packageFlags

type (
	packageFlags struct {
		specPath               string
		packageVersion         string
		sdkVersion             string
		registryURL            string
		registryBaseRepository string
		registryAuthEnabled    bool
		registryAuthUsername   string
		registryAuthPassword   string
	}
)

// NewPackageCommand returns a new package command.
func NewPackageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: "Packages a component's configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := packageComponent(cmd.Context(), packageCmdFlags); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}

	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.specPath,
			"spec-path",
			".",
			"the location of the component spec file",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.packageVersion,
			"version",
			"",
			"the version to be used to package the component",
		)
	_ = cmd.MarkFlagRequired("version")
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.sdkVersion,
			"sdk-version",
			"",
			"the version the sdk used to build the component",
		)
	_ = cmd.MarkFlagRequired("sdk-version")
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.registryURL,
			"registry-url",
			"ghcr.io",
			"the reference to the OCI compliant registry",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.registryBaseRepository,
			"registry-base-repository",
			"smithy-security/manifests/components",
			"the repository where to push manifests to",
		)
	cmd.
		Flags().
		BoolVar(
			&packageCmdFlags.registryAuthEnabled,
			"registry-auth-enabled",
			false,
			"if enabled, it requires authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.registryAuthUsername,
			"registry-auth-username",
			"",
			"the username used for authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.registryAuthPassword,
			"registry-auth-password",
			"",
			"the password used for authentication for the registry",
		)

	return cmd
}

func packageComponent(ctx context.Context, flags packageFlags) error {
	c, err := component.NewSpecParser().Parse(flags.specPath)
	if err != nil {
		return err
	}

	reg, err := registry.New(
		flags.registryURL,
		flags.registryBaseRepository,
		flags.registryAuthEnabled,
		flags.registryAuthUsername,
		flags.registryAuthPassword,
	)
	if err != nil {
		return errors.Errorf("failed to initialize registry: %w", err)
	}

	if err := reg.Package(ctx, registry.PackageRequest{
		Component:        c,
		SDKVersion:       flags.sdkVersion,
		ComponentVersion: flags.packageVersion,
	}); err != nil {
		return errors.Errorf("failed to package component: %w", err)
	}

	return nil
}
