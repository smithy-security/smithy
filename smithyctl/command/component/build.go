package component

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/internal/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/internal/images/docker"
)

var buildCmdFlags buildFlags

type (
	buildFlags struct {
		registry                string
		registryAuthUsername    string
		registryAuthPassword    string
		namespace               string
		baseComponentDockerfile string
		labels                  []string
		labelsMap               map[string]string
		push                    bool
		platform                string
		tags                    []string
	}
)

// NewBuildCommand returns a new build command.
func NewBuildCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Builds a component's containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := parseFlagsAndBuildImages(cmd.Context(), buildCmdFlags, args); err != nil {
				return errors.Errorf("unexpected failure: %w", err)
			}
			return nil
		},
	}

	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.registry,
			"registry",
			images.DefaultRegistry,
			"registry to use for the images",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.namespace,
			"namespace",
			images.DefaultNamespace,
			"namespace that will be added to all the images built by the system",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.baseComponentDockerfile,
			"base-component-dockerfile",
			"new-components/Dockerfile",
			"base Dockerfile to use to build all the images",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.registryAuthUsername,
			"registry-auth-username",
			"",
			"username to authenticate with for the image registry",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.registryAuthPassword,
			"registry-auth-password",
			"",
			"password to authenticate with for the image registry",
		)
	cmd.
		Flags().
		StringSliceVar(
			&buildCmdFlags.labels,
			"label",
			nil,
			fmt.Sprintf("labels to add to the image, you can set multiple instances of --label 'key=var'. (default are %q)", images.DefaultLabels),
		)
	cmd.
		Flags().
		BoolVar(
			&buildCmdFlags.push,
			"push",
			false,
			"push images once they are built",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.platform,
			"platform",
			"",
			"build an image for a platform other than one where the Docker server is running",
		)
	cmd.
		Flags().
		StringSliceVar(
			&buildCmdFlags.tags,
			"tag",
			[]string{images.DefaultTag},
			"tags to use for images, can be multiple",
		)

	return cmd
}

func parseFlagsAndBuildImages(ctx context.Context, flags buildFlags, args []string) error {
	if len(args) != 1 {
		return errors.New("you need to provide exactly one path to a component YAML spec")
	}

	componentPath := args[0]
	if info, err := os.Stat(componentPath); err != nil {
		return errors.Errorf("%s: could not find component YAML spec: %w", componentPath, err)
	} else if info.IsDir() || !info.Mode().IsRegular() {
		return errors.Errorf("path should be pointing to a component YAML spec: %s", componentPath)
	}

	if buildCmdFlags.registryAuthPassword != "" && buildCmdFlags.registryAuthUsername == "" {
		return errors.New("if you set the registry auth password you also need to set the username")
	} else if buildCmdFlags.registryAuthPassword == "" && buildCmdFlags.registryAuthUsername != "" {
		return errors.New("if you set the registry auth username you also need to set the password")
	}

	baseDockerfilePath := buildCmdFlags.baseComponentDockerfile
	if info, err := os.Stat(baseDockerfilePath); err != nil {
		return errors.Errorf("%s: could not find base Dockerfile: %w", baseDockerfilePath, err)
	} else if info.IsDir() || !info.Mode().IsRegular() {
		return errors.Errorf("path should be base Dockerfile not directory or irregular file: %s", baseDockerfilePath)
	}

	_, err := url.Parse(buildCmdFlags.registry)
	if err != nil {
		return errors.Errorf("%s: there was an error parsing the URL of the registry: %w", buildCmdFlags.registry, err)
	}

	buildCmdFlags.labelsMap = map[string]string{}
	for _, label := range buildCmdFlags.labels {
		labelParts := strings.Split(label, "=")
		if len(labelParts) != 2 {
			return errors.Errorf("%s: each label should be formated as key=value", label)
		}

		buildCmdFlags.labelsMap[labelParts[0]] = labelParts[1]
	}

	return buildComponent(ctx, flags, componentPath)
}

func buildComponent(ctx context.Context, flags buildFlags, componentPath string) error {
	buildOpts := []dockerimages.BuilderOptionFn{}
	if flags.baseComponentDockerfile != "" {
		buildOpts = append(buildOpts, dockerimages.WithBaseDockerfilePath(flags.baseComponentDockerfile))
	}

	if len(flags.labelsMap) > 0 {
		buildOpts = append(buildOpts, dockerimages.WithLabels(flags.labelsMap))
	}

	if flags.push {
		buildOpts = append(buildOpts, dockerimages.PushImages())
	}

	if flags.platform != "" {
		buildOpts = append(buildOpts, dockerimages.WithPlatform(flags.platform))
	}

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return errors.Errorf("failed to bootstrap docker client: %w", err)
	}

	dockerBuilder, err := dockerimages.NewBuilder(ctx, dockerClient, componentPath, buildOpts...)
	if err != nil {
		return errors.Errorf("could not bootstrap docker builder: %w", err)
	}

	componentParser := component.NewSpecParser()
	component, err := componentParser.Parse(componentPath)
	if err != nil {
		return errors.Errorf("%s: could not parse component spec: %w", componentPath, err)
	}

	imageResolutionOpts := []images.ResolutionOptionFn{}
	if flags.namespace != "" {
		imageResolutionOpts = append(imageResolutionOpts, images.WithNamespace(flags.namespace))
	}

	imageResolutionOpts = append(imageResolutionOpts, images.WithDefaultTag(flags.tags[0]))
	if len(flags.tags) > 1 {
		imageResolutionOpts = append(imageResolutionOpts, images.WithExtraTags(flags.tags[1:]...))
	}

	if flags.registry != "" {
		imageResolutionOpts = append(imageResolutionOpts, images.WithRegistry(flags.registry))
	}

	for _, step := range component.Steps {
		cr, parsedRef, err := images.ParseComponentRepository(componentPath, step.Image, imageResolutionOpts...)
		if errors.Is(err, images.ErrNotAComponentRepo) {
			fmt.Fprintf(os.Stderr, "skipping external image: %s\n", parsedRef.String())
			continue
		} else if err != nil {
			return errors.Errorf("%s, %s: could not parse image reference: %w", step.Name, step.Image, err)
		}

		resolvedImage, err := dockerBuilder.Build(ctx, cr)
		if err != nil {
			return errors.Errorf("%s, %s: %w", step.Name, step.Image, err)
		}

		fmt.Fprintf(os.Stderr, "finalised building of image %s\n", resolvedImage)
	}

	return nil
}
