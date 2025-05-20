package workflow

import (
	"context"
	"os"

	dockerclient "github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/smithy-security/smithy/smithyctl/component"
	"github.com/smithy-security/smithy/smithyctl/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/images/docker"
	"github.com/smithy-security/smithy/smithyctl/internal/command/workflow"
	"github.com/smithy-security/smithy/smithyctl/internal/creds"
	"github.com/smithy-security/smithy/smithyctl/internal/engine"
	dockerexecutor "github.com/smithy-security/smithy/smithyctl/internal/engine/docker"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

var runCmdFlags runFlags

type runFlags struct {
	overridesPath string

	registryURL             string
	namespace               string
	registryAuthEnabled     bool
	registryAuthUsername    string
	registryAuthPassword    string
	imageRegistry           string
	imageNamespace          string
	baseComponentDockerfile string

	cleanRun             bool
	buildComponentImages bool
}

// NewRunCommand returns a new run workflow command.
func NewRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Allows running workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWorkflow(cmd.Context(), runCmdFlags, args)
		},
	}

	cmd.
		Flags().
		StringVar(
			&runCmdFlags.overridesPath,
			"overrides",
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
			&runCmdFlags.namespace,
			"namespace",
			"smithy-security/smithy/manifests/components",
			"the repository namespace to push manifests to",
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
	cmd.
		Flags().
		BoolVar(
			&runCmdFlags.buildComponentImages,
			"build-component-images",
			false,
			"build any component images whose tag is set to latest listed in components from the local filesystem",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.imageRegistry,
			"image-registry",
			"",
			"registry to use for the images",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.imageNamespace,
			"image-namespace",
			images.DefaultNamespace,
			"namespace that will be added to all the images built by the system",
		)
	cmd.
		Flags().
		StringVar(
			&runCmdFlags.baseComponentDockerfile,
			"base-component-dockerfile",
			"components/Dockerfile",
			"base Dockerfile to use to build all the images",
		)

	return cmd
}

func runWorkflow(ctx context.Context, flags runFlags, args []string) error {
	if len(args) != 1 {
		return errors.New("you need to set exactly one positional argument with the path to the workflow spec")
	}

	workflowPath := args[0]
	if info, err := os.Stat(workflowPath); err != nil {
		return errors.Errorf("%s: could not find component YAML spec: %w", workflowPath, err)
	} else if info.IsDir() || !info.Mode().IsRegular() {
		return errors.Errorf("path should be pointing to a component YAML spec: %s", workflowPath)
	}

	var credsStore credentials.Store
	var err error
	if flags.registryAuthEnabled {
		credsStore, err = creds.NewStaticStore(
			flags.registryURL, flags.registryAuthUsername, flags.registryAuthPassword,
		)
	} else {
		credsStore, err = credentials.NewStoreFromDocker(credentials.StoreOptions{
			DetectDefaultNativeStore: true,
		})
	}
	if err != nil {
		return errors.Errorf("could not initialise credential store: %w", err)
	}

	reg, err := registry.New(
		flags.registryURL,
		flags.namespace,
		false,
		credsStore,
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
	if runCmdFlags.imageRegistry != "" {
		imageResolutionOptions = append(imageResolutionOptions, images.WithRegistry(runCmdFlags.registryURL))
	}

	if runCmdFlags.imageNamespace != "" {
		imageResolutionOptions = append(imageResolutionOptions, images.WithNamespace(runCmdFlags.imageNamespace))
	}

	buildOptions := []dockerimages.BuilderOptionFn{}
	if runCmdFlags.baseComponentDockerfile != "" {
		buildOptions = append(buildOptions, dockerimages.WithBaseDockerfilePath(runCmdFlags.baseComponentDockerfile))
	}

	imageResolver, err := workflow.NewDockerImageResolver(
		flags.buildComponentImages,
		dockerClient,
		credsStore,
		buildOptions...,
	)
	if err != nil {
		return errors.Errorf("could not bootstrap image resolver: %w", err)
	}

	parser, err := workflow.NewSpecParser(reg, component.NewSpecParser(), imageResolver)
	if err != nil {
		return errors.Errorf("failed to initialize workflow spec parser: %w", err)
	}

	wf, err := parser.Parse(
		ctx,
		workflow.ParserConfig{
			SpecPath:       workflowPath,
			OverridesPath:  flags.overridesPath,
			ResolutionOpts: imageResolutionOptions,
		},
	)
	if err != nil {
		return errors.Errorf("failed to parse workflow spec: %w", err)
	}

	dockerExec, err := dockerexecutor.NewExecutor(dockerClient)
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
