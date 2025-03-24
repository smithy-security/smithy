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
	"gopkg.in/yaml.v3"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/internal/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/internal/images/docker"
)

var buildCmdFlags buildFlags

type (
	buildFlags struct {
		registry                string
		username                string
		authEnabled             bool
		password                string
		namespace               string
		baseComponentDockerfile string
		labels                  []string
		labelsMap               map[string]string
		dryRun                  bool
		push                    bool
		platform                string
		tags                    []string
		sdkVersion              string
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
			"registry-url",
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
		BoolVar(
			&buildCmdFlags.authEnabled,
			"registry-auth-enabled",
			false,
			"use username and password to authenticate to the OCI registry",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.username,
			"registry-auth-username",
			"",
			"username to authenticate with for the image registry",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.password,
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
			[]string{"latest"},
			"tags to use for images, can be multiple",
		)
	cmd.
		Flags().
		StringVar(
			&buildCmdFlags.sdkVersion,
			"sdk-version",
			"",
			"sdk-version passed to build components",
		)
	cmd.
		Flags().
		BoolVar(
			&buildCmdFlags.dryRun,
			"dry-run",
			false,
			"don't build the images but show a report of what the system would execute",
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

	if buildCmdFlags.authEnabled {
		if buildCmdFlags.password == "" || buildCmdFlags.username == "" {
			return errors.New("you need to set both the registry username and password")
		}
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

	if flags.authEnabled {
		buildOpts = append(buildOpts, dockerimages.WithUsernamePassword(flags.username, flags.password))
	}

	if flags.sdkVersion != "" {
		buildOpts = append(buildOpts, dockerimages.WithSDKVersion(flags.sdkVersion))
	}

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return errors.Errorf("failed to bootstrap docker client: %w", err)
	}

	dockerResolverBuilder, err := dockerimages.NewResolverBuilder(
		ctx,
		dockerClient,
		componentPath,
		flags.dryRun,
		buildOpts...,
	)
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

	imageResolutionOpts = append(imageResolutionOpts, images.WithTags(flags.tags...))

	if flags.registry != "" {
		imageResolutionOpts = append(imageResolutionOpts, images.WithRegistry(flags.registry))
	}

	for _, step := range component.Steps {
		resolvedImage, err := dockerResolverBuilder.Resolve(ctx, step.Image, imageResolutionOpts...)
		if err != nil {
			return errors.Errorf("%s, %s: %w", step.Name, step.Image, err)
		}

		fmt.Fprintf(os.Stderr, "finished resolving image %s\n", resolvedImage)
	}

	if flags.dryRun {
		return yaml.NewEncoder(os.Stdout).Encode(dockerResolverBuilder.Report())
	}

	return nil
}
