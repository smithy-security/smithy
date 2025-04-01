package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"text/template"

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

	TmpFolderProvisioner func(instanceID uuid.UUID, folderType string) (string, error)

	// ContainerConfig stripped down configuration that we need to run simple containers.
	ContainerConfig struct {
		Name           string
		Image          string
		Executable     string
		Cmd            []string
		EnvVars        []string
		VolumeBindings []string
		Platform       *ocispec.Platform
	}

	// ExecutorConfig allows to customise the executor behaviour.
	ExecutorConfig struct {
		CleanUpFindingsDB   bool
		InstanceIDGenerator InstanceIDGenerator
		TmpFolderProvisioner
	}

	volumeDescription struct {
		mountPath string
		hostPath  string
	}

	executor struct {
		containerExec  ContainerExecutor
		conf           *ExecutorConfig
		instanceID     uuid.UUID
		volumeRequests map[string]volumeDescription
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

	if conf.TmpFolderProvisioner == nil {
		conf.TmpFolderProvisioner = func(instanceID uuid.UUID, folderType string) (string, error) {
			folderNamePattern := folderType + "-" + instanceID.String() + "-*"
			tmpDir, err := os.MkdirTemp("", folderNamePattern)
			if err != nil {
				return "", errors.Errorf("could not provision temporary folder with name %s: %w", folderNamePattern, err)
			}

			return tmpDir, nil
		}
	}

	return &executor{
		containerExec:  containerExecutor,
		conf:           conf,
		volumeRequests: map[string]volumeDescription{},
	}, nil
}

// Execute runs each step in each stage after creating an instance ID.
// It also cleans up the environment post run.
func (e *executor) Execute(ctx context.Context, wf *v1Types.Workflow) error {
	e.instanceID = e.conf.InstanceIDGenerator()

	defer e.cleanup(ctx)

	for _, stage := range wf.Stages {
		for _, ref := range stage.ComponentRefs {
			sharedComponentVolumes := map[string]volumeDescription{}
			for _, step := range ref.Component.Steps {
				if err := e.executeStep(ctx, step, sharedComponentVolumes); err != nil {
					return errors.Errorf("failed to run step for component '%s': %w", ref.Component.Name, err)
				}
			}
		}
	}

	return nil
}

func (e *executor) render(templStr string, funcMaps template.FuncMap) (string, error) {
	// we initialise the template over and over in order to ensure that we have
	// a view of the errors occurring while the template is parsed
	tmpl, err := template.New("templStr").Funcs(funcMaps).Parse(templStr)
	if err != nil {
		return "", err
	}

	var bb bytes.Buffer
	err = tmpl.Execute(&bb, nil)
	if err != nil {
		return "", errors.Errorf("%s: could not render template: %w", templStr, err)
	}

	return bb.String(), nil
}

func (e *executor) renderVolumes(
	step v1Types.Step,
	sharedComponentVolumes map[string]volumeDescription,
) ([]volumeDescription, error) {
	var renderErr error
	volumeRequests := map[string]volumeDescription{}

	// this is used to create a temporary directory that will be mounted to all
	// the containers of the execution if they request them
	sharedTmpFolder := func(volumeReqID string) string {
		if _, exists := e.volumeRequests[volumeReqID]; !exists {
			tmpDir, err := e.conf.TmpFolderProvisioner(e.instanceID, volumeReqID)
			if err != nil {
				renderErr = errors.Join(renderErr, err)
			}

			e.volumeRequests[volumeReqID] = volumeDescription{
				mountPath: fmt.Sprintf("/workspace/%s", volumeReqID),
				hostPath:  tmpDir,
			}
		}

		volumeRequests[volumeReqID] = e.volumeRequests[volumeReqID]
		return e.volumeRequests[volumeReqID].mountPath
	}

	funcMaps := template.FuncMap{
		"scratchWorkspace": func() string {
			// this should be unique per component
			if _, exists := sharedComponentVolumes["scratch"]; !exists {
				tmpDir, err := e.conf.TmpFolderProvisioner(e.instanceID, "scratch")
				if err != nil {
					renderErr = errors.Join(renderErr, err)
				}

				sharedComponentVolumes["scratch"] = volumeDescription{
					mountPath: "/workspace/scratch",
					hostPath:  tmpDir,
				}
			}

			volumeRequests["scratch"] = sharedComponentVolumes["scratch"]
			return volumeRequests["scratch"].mountPath
		},
		"sourceCodeWorkspace": func() string {
			return sharedTmpFolder("source-code")
		},
		"targetMetadataWorkspace": func() string {
			return sharedTmpFolder("target-metadata")
		},
	}

	for name, val := range step.EnvVars {
		newVal, err := e.render(val, funcMaps)
		if err != nil {
			return nil, errors.Errorf("could not render expression: %w", err)
		}

		if renderErr != nil {
			return nil, errors.Errorf("could not render expression: %w", renderErr)
		}

		step.EnvVars[name] = newVal
	}

	for index, arg := range step.Args {
		newVal, err := e.render(arg, funcMaps)
		if err != nil {
			return nil, errors.Errorf("could not render expression: %w", err)
		}

		if renderErr != nil {
			return nil, errors.Errorf("could not render expression: %w", renderErr)
		}

		step.Args[index] = newVal
	}

	if step.Script != "" {
		newVal, err := e.render(step.Script, funcMaps)
		if err != nil {
			return nil, errors.Errorf("could not render expression: %w", err)
		}

		if renderErr != nil {
			return nil, errors.Errorf("could not render expression: %w", renderErr)
		}

		step.Script = newVal
	}

	return slices.Collect(maps.Values(volumeRequests)), nil
}

// executeStep builds the container run context and runs the container on the passed execution backend.
func (e *executor) executeStep(
	ctx context.Context,
	step v1Types.Step,
	sharedComponentVolumes map[string]volumeDescription,
) error {
	ref, err := name.ParseReference(step.Image)
	if err != nil {
		return errors.Errorf("failed to determine reference for step '%s': %w", step.Name, err)
	}

	var (
		refCtx = ref.Context()
		image  = path.Join(refCtx.RegistryStr(), refCtx.RepositoryStr())
		tag    = ref.Identifier()
	)

	if step.Executable == "" {
		return errors.Errorf("%s: you need to set an executable absolute path for each step", step.Name)
	}

	stepVolumes, err := e.renderVolumes(step, sharedComponentVolumes)
	if err != nil {
		return errors.Errorf("%s: could not render step: %w", step.Name, err)
	}

	absPath, err := filepath.Abs(".")
	if err != nil {
		return errors.Errorf("failed to determine absolute path: %w", err)
	}

	volumeBindings := []string{
		path.Join(absPath, fmt.Sprintf("%s:/workspace", smithyDir)),
	}

	for _, stepVolume := range stepVolumes {
		volumeBindings = append(volumeBindings, stepVolume.hostPath+":"+stepVolume.mountPath)
	}

	envVars := []string{
		fmt.Sprintf("SMITHY_INSTANCE_ID=%s", e.instanceID.String()),
		"SMITHY_LOG_LEVEL=debug",
	}

	for k, v := range step.EnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
	}

	// these are just used to make it easier to test this code so that
	// we can predict the order of the items in the lists and gomock
	// doesn't bother us
	slices.Sort(volumeBindings)
	slices.Sort(envVars)
	if err := e.containerExec.RunAndWait(
		ctx,
		ContainerConfig{
			Name:           step.Name,
			Image:          fmt.Sprintf("%s:%s", image, tag),
			Executable:     step.Executable,
			Cmd:            step.Args,
			EnvVars:        envVars,
			VolumeBindings: volumeBindings,
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
