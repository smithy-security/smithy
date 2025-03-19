package component

import (
	"context"
	"os"

	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/internal/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/internal/images/docker"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

var packageCmdFlags packageFlags

type (
	packageFlags struct {
		packageVersion         string
		sdkVersion             string
		registryURL            string
		registryBaseRepository string
		registryAuthEnabled    bool
		registryAuthUsername   string
		registryAuthPassword   string
		imageRegistryURL       string
		imageNamespace         string
		imageTag               string
		dryRun                 bool
	}
)

// NewPackageCommand returns a new package command.
func NewPackageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: "Packages a component's configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("you need to provide exactly one positional argument with a path to a component YAML spec")
			}

			if err := packageComponent(cmd.Context(), packageCmdFlags, args[0]); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}

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
			images.DefaultRegistry,
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
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.imageRegistryURL,
			"image-registry-url",
			images.DefaultRegistry,
			"the registry used for component images",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.imageNamespace,
			"image-namespace",
			images.DefaultNamespace,
			"the namespace used for component images",
		)
	cmd.
		Flags().
		StringVar(
			&packageCmdFlags.imageTag,
			"image-tag",
			images.DefaultTag,
			"the container tag used for the component images",
		)
	cmd.
		Flags().
		BoolVar(
			&packageCmdFlags.dryRun,
			"dry-run",
			false,
			"output rendered component YAML to stderr",
		)

	return cmd
}

func packageComponent(ctx context.Context, flags packageFlags, componentPath string) error {
	componentSpec, err := component.
		NewSpecParser().
		Parse(componentPath)
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

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return errors.Errorf("failed to bootstrap docker client: %w", err)
	}

	imageResolutionOptions := []images.ResolutionOptionFn{}
	if packageCmdFlags.imageRegistryURL != "" {
		imageResolutionOptions = append(imageResolutionOptions, images.WithRegistry(packageCmdFlags.registryURL))
	}

	if packageCmdFlags.imageNamespace != "" {
		imageResolutionOptions = append(imageResolutionOptions, images.WithNamespace(packageCmdFlags.imageNamespace))
	}

	imageResolver, err := dockerimages.NewResolverBuilder(
		ctx, dockerClient, componentPath, true,
	)
	if err != nil {
		return errors.Errorf("could not bootstrap image resolver: %w", err)
	}

	for stepIndex, step := range componentSpec.Steps {
		renderedImage, err := imageResolver.Resolve(ctx, step.Image, imageResolutionOptions...)
		if err != nil {
			return errors.Errorf("could not resolve component's image: %w", err)
		}

		step.Image = renderedImage
		componentSpec.Steps[stepIndex] = step
	}

	if flags.dryRun {
		return yaml.NewEncoder(os.Stdout).Encode(componentSpec)
	}

	if err := reg.Package(ctx, registry.PackageRequest{
		Component:        componentSpec,
		SDKVersion:       flags.sdkVersion,
		ComponentVersion: flags.packageVersion,
	}); err != nil {
		return errors.Errorf("failed to package component: %w", err)
	}

	return nil
}
