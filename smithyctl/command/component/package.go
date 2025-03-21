package component

import (
	"context"
	"os"
	"path"
	"strings"

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
		packageVersion       string
		sdkVersion           string
		registryURL          string
		namespace            string
		annotations          []string
		registryAuthEnabled  bool
		registryAuthUsername string
		registryAuthPassword string
		imageRegistryURL     string
		imageNamespace       string
		imageTag             string
		dryRun               bool
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
			&packageCmdFlags.namespace,
			"namespace",
			"smithy-security/manifests",
			"the namespace of the repository where to push manifests to",
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
			"",
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
	cmd.
		Flags().
		StringSliceVar(
			&packageCmdFlags.annotations,
			"annotation",
			[]string{"org.opencontainers.image.source=https://github.com/smithy-security/smithy"},
			"annotation to add to the package. It must be of the form key=value",
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
		flags.namespace,
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

	if packageCmdFlags.imageTag != "" {
		imageResolutionOptions = append(imageResolutionOptions, images.WithTags(packageCmdFlags.imageTag))
	} else {
		imageResolutionOptions = append(imageResolutionOptions, images.WithTags(packageCmdFlags.packageVersion))
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

	annotations := map[string]string{}
	for _, annotation := range flags.annotations {
		annotationSubString := strings.SplitN(annotation, "=", 2)
		if len(annotationSubString) != 2 {
			return errors.Errorf("could not process %s into a key=value form", annotation)
		}
		annotations[annotationSubString[0]] = annotationSubString[1]
	}

	if err := reg.Package(ctx, registry.PackageRequest{
		ComponentPath:    path.Dir(componentPath),
		Component:        componentSpec,
		SDKVersion:       flags.sdkVersion,
		ComponentVersion: flags.packageVersion,
		Annotations:      annotations,
	}); err != nil {
		return errors.Errorf("failed to package component: %w", err)
	}

	return nil
}
