package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	v1Types "github.com/smithy-security/smithy/pkg/types/v1"
	"github.com/smithy-security/smithy/sdk/component/uuid"

	"github.com/smithy-security/smithy/smithyctl/internal/logging"
)

const (
	smithyDir  = ".smithy"
	dbLocation = ".smithy/smithy.db"
)

type (
	// ContainerExecutor can be implemented to execute containers with different backends.
	ContainerExecutor interface {
		RunAndWait(ctx context.Context, conf ContainerConfig) error
	}

	InstanceIDGenerator func() uuid.UUID

	// ContainerConfig stripped down configuration that we need to run simple containers.
	ContainerConfig struct {
		Name           string
		Image          string
		Cmd            []string
		EnvVars        []string
		VolumeBindings []string
		Platform       *ocispec.Platform
	}

	// ExecutorConfig allows to customise the executor behaviour.
	ExecutorConfig struct {
		CleanUpFindingsDB   bool
		InstanceIDGenerator InstanceIDGenerator
	}

	executor struct {
		containerExec ContainerExecutor
		conf          *ExecutorConfig
	}
)

// NewExecutor returns a new executor.
func NewExecutor(containerExecutor ContainerExecutor, conf *ExecutorConfig) (*executor, error) {
	if containerExecutor == nil {
		return nil, errors.New("invalid nil container executor")
	}

	if conf.InstanceIDGenerator == nil {
		conf.InstanceIDGenerator = uuid.New
	}

	return &executor{
		containerExec: containerExecutor,
		conf:          conf,
	}, nil
}

// Execute runs each step in each stage after creating an instance ID.
// It also cleans up the environment post run.
func (e *executor) Execute(ctx context.Context, wf *v1Types.Workflow) error {
	instanceID := e.conf.InstanceIDGenerator()

	defer e.cleanup(ctx)

	for _, stage := range wf.Stages {
		for _, ref := range stage.ComponentRefs {
			for _, step := range ref.Component.Steps {
				if err := e.executeStep(ctx, instanceID, step); err != nil {
					return errors.Errorf("failed to run step for component '%s': %w", ref.Component.Name, err)
				}
			}
		}
	}

	return nil
}

// executeStep builds the container run context and runs the container on the passed execution backend.
func (e *executor) executeStep(ctx context.Context, instanceID uuid.UUID, step v1Types.Step) error {
	absPath, err := filepath.Abs(".")
	if err != nil {
		return errors.Errorf("failed to determine absolute path: %w", err)
	}

	ref, err := name.ParseReference(step.Image)
	if err != nil {
		return errors.Errorf("failed to determine reference for step '%s': %w", step.Name, err)
	}

	var (
		refCtx = ref.Context()
		image  = path.Join(refCtx.RegistryStr(), refCtx.RepositoryStr())
		tag    = ref.Identifier()
	)

	envVars := []string{
		fmt.Sprintf("SMITHY_INSTANCE_ID=%s", instanceID.String()),
		"SMITHY_LOG_LEVEL=debug",
	}

	for k, v := range step.EnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
	}

	var cmd = make([]string, 0)
	if step.Executable != "" {
		cmd = append([]string{step.Executable}, step.Args...)
	}

	if err := e.containerExec.RunAndWait(
		ctx,
		ContainerConfig{
			Name:    step.Name,
			Image:   fmt.Sprintf("%s:%s", image, tag),
			Cmd:     cmd,
			EnvVars: envVars,
			VolumeBindings: []string{
				// This is shared between all containers for simplicity.
				path.Join(absPath, fmt.Sprintf("%s:/workspace", smithyDir)),
				fmt.Sprintf("%s:/workspace/repos", os.TempDir()),
			},
			// Standardising the platform to avoid not fun issues on different OS/ARCH.
			Platform: &ocispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
	); err != nil {
		return errors.Errorf("failed to execute step '%s': %w", step.Name, err)
	}

	return nil
}

func (e *executor) cleanup(ctx context.Context) {
	logger := logging.FromContext(ctx)

	if e.conf.CleanUpFindingsDB {
		if err := os.RemoveAll(dbLocation); err != nil {
			logger.Error(
				"could not remove findings database",
				slog.String("path", dbLocation),
				slog.String("err", err.Error()),
			)
		}
	}
}
