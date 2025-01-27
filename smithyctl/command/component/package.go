package component

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithyctl/internal/registry"
)

var flags packageFlags

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
			if err := packageComponent(cmd.Context(), flags); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}

	cmd.
		Flags().
		StringVar(
			&flags.specPath,
			"spec-path",
			".",
			"the location of the component spec file",
		)
	cmd.
		Flags().
		StringVar(
			&flags.packageVersion,
			"version",
			"",
			"the version to be used to package the component",
		)
	_ = cmd.MarkFlagRequired("version")
	cmd.
		Flags().
		StringVar(
			&flags.sdkVersion,
			"sdk-version",
			"",
			"the version the sdk used to build the component",
		)
	_ = cmd.MarkFlagRequired("sdk-version")
	cmd.
		Flags().
		StringVar(
			&flags.registryURL,
			"registry-url",
			"ghcr.io",
			"the reference to the OCI compliant registry",
		)
	cmd.
		Flags().
		StringVar(
			&flags.registryBaseRepository,
			"registry-base-repository",
			"smithy-security/manifests/components",
			"the repository where to push manifests to",
		)
	cmd.
		Flags().
		BoolVar(
			&flags.registryAuthEnabled,
			"registry-auth-enabled",
			false,
			"if enabled, it requires authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&flags.registryAuthUsername,
			"registry-auth-username",
			"",
			"the username used for authentication for the registry",
		)
	cmd.
		Flags().
		StringVar(
			&flags.registryAuthPassword,
			"registry-auth-password",
			"",
			"the password used for authentication for the registry",
		)

	return cmd
}

func packageComponent(ctx context.Context, flags packageFlags) error {
	component, err := parseComponentSpec(flags.specPath)
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
		Component:        component,
		SDKVersion:       flags.sdkVersion,
		ComponentVersion: flags.packageVersion,
	}); err != nil {
		return errors.Errorf("failed to package component: %w", err)
	}

	return nil
}

func parseComponentSpec(path string) (*v1.Component, error) {
	const (
		defaultSmithyComponentFileNameYaml = "component.yaml"
		defaultSmithyComponentFileNameYml  = "component.yml"
	)

	if !strings.HasSuffix(path, defaultSmithyComponentFileNameYaml) && !strings.HasSuffix(path, defaultSmithyComponentFileNameYml) {
		return nil, errors.Errorf(
			"invalid file path %s, has to either point to a component file",
			path,
		)
	}

	// If the path doesn't exist, we return.
	info, err := os.Stat(path)
	switch {
	case err != nil:
		if os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("%s does not exist", path))
		}
		return nil, fmt.Errorf("failed check config file: %w", err)
	case info.IsDir():
		return nil, errors.New(fmt.Sprintf("%s is a directory", path))
	case !strings.HasSuffix(path, defaultSmithyComponentFileNameYaml) && !strings.HasSuffix(path, defaultSmithyComponentFileNameYml):
		return nil, errors.Errorf(
			"invalid file path %s, has to either point to a component file",
			path,
		)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed read config file: %w", err)
	}

	var component v1.Component
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&component); err != nil {
		return nil, fmt.Errorf("failed decode file '%s': %w", path, err)
	}

	if err := component.Validate(); err != nil {
		return nil, errors.Errorf("invalid component spec: %w", err)
	}

	return &component, nil
}
