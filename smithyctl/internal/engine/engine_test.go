package engine_test

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
	"github.com/smithy-security/smithy/sdk/component/uuid"

	"github.com/smithy-security/smithy/smithyctl/internal/engine"
)

func TestNewExecutor(t *testing.T) {
	ctrl := gomock.NewController(t)

	t.Run("it returns an error when the container executor is nil", func(t *testing.T) {
		exe, err := engine.NewExecutor(nil, &engine.ExecutorConfig{})
		require.Error(t, err)
		require.Nil(t, exe)
	})
	t.Run("it returns a new executor", func(t *testing.T) {
		exe, err := engine.NewExecutor(NewMockContainerExecutor(ctrl), &engine.ExecutorConfig{})
		require.NoError(t, err)
		require.NotNil(t, exe)
	})
}

func appendAndSort(sl []string, s ...string) []string {
	nsl := append(sl, s...)
	slices.Sort(nsl)
	return nsl
}

func TestExecutor_Execute(t *testing.T) {
	const (
		targetComponentName        = "target-component-name"
		targetComponentStepName    = "clone"
		targetComponentImage       = "ghcr.io/smithy-security/smithy/components/targets/git-clone:latest"
		scanner1ComponentName      = "scanner-component-name-1"
		scanner1ComponentStepName1 = "scanner-1"
		scanner1ComponentStepName2 = "scanner-3"
		scanner1ComponentImage     = "ghcr.io/smithy-security/smithy/components/scanners/scanner-1:latest"
		scanner2ComponentName      = "scanner-component-name-2"
		scanner2ComponentImage     = "ghcr.io/smithy-security/smithy/components/scanners/scanner-2:latest"
		scanner2ComponentStepName  = "scanner-2"
		enricherComponentName      = "enricher-component-name"
		enricherComponentImage     = "ghcr.io/smithy-security/smithy/components/enrichers/enricher:latest"
		enricherComponentStepName  = "enricher"
		filterComponentName        = "filter-component-name"
		filterComponentImage       = "ghcr.io/smithy-security/smithy/components/filters/filter:latest"
		filterComponentStepName    = "filter"
		reporterComponentName      = "reporter-component-name"
		reporterComponentImage     = "ghcr.io/smithy-security/smithy/components/reporters/reporter:latest"
		reporterComponentStepName  = "reporter"
	)

	instanceID, err := uuid.Parse("37087cc2-e4ba-4fe0-8230-cda372778ed7")
	require.NoError(t, err)

	absPath, err := filepath.Abs(".")
	require.NoError(t, err)

	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		ctrl        = gomock.NewController(t)
		idGenerator = func() uuid.UUID {
			return instanceID
		}
		tmpFolderProvisioner = func(instanceIDForTmpFolder uuid.UUID, s string) (string, error) {
			require.Equal(t, instanceID, instanceIDForTmpFolder)
			require.True(t, s == "scratch" || s == "source-code" || s == "target-metadata")

			return "/tmp/" + instanceIDForTmpFolder.String() + "-" + s, nil
		}
		sourceCodeHostPath      = "/tmp/" + instanceID.String() + "-source-code"
		scratchHostPath         = "/tmp/" + instanceID.String() + "-scratch"
		targetMetdatadaHostPath = "/tmp/" + instanceID.String() + "-target-metadata"
		sourceCodeMountPath     = "/workspace/source-code"
		scratchMountPath        = "/workspace/scratch"
		targetMetadataMountPath = "/workspace/target-metadata"
		mockContainerExec       = NewMockContainerExecutor(ctrl)
		workflow                = &v1.Workflow{
			Name:        "test-workflow",
			Description: "test workflow",
			Stages: []v1.Stage{
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Name:        targetComponentName,
								Description: "target-component-descr",
								Type:        v1.ComponentTypeTarget,
								Steps: []v1.Step{
									{
										Name:  targetComponentStepName,
										Image: targetComponentImage,
										EnvVars: map[string]string{
											"REPO_URL": "github.com/andream16/tree",
										},
										Args:       []string{"{{ sourceCodeWorkspace }}"},
										Executable: "/bin/clone",
									},
								},
							},
						},
					},
				},
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Name:        scanner1ComponentName,
								Description: "scanner-component-descr-1",
								Type:        v1.ComponentTypeScanner,
								Steps: []v1.Step{
									{
										Name:       scanner1ComponentStepName1,
										Image:      scanner1ComponentImage,
										Executable: "/bin/prescan",
										Args:       []string{"--from={{ sourceCodeWorkspace }}", "--to={{ scratchWorkspace }}"},
									},
									{
										Name:       scanner1ComponentStepName2,
										Image:      scanner1ComponentImage,
										Executable: "/bin/scan",
										Args:       []string{"{{ scratchWorkspace }}"},
									},
								},
							},
						},
						{
							Component: v1.Component{
								Name:        scanner2ComponentName,
								Description: "scanner-component-descr-2",
								Type:        v1.ComponentTypeScanner,
								Steps: []v1.Step{
									{
										Name:       scanner2ComponentStepName,
										Image:      scanner2ComponentImage,
										Executable: "/bin/scan",
										EnvVars: map[string]string{
											"FROM": "{{ sourceCodeWorkspace }}",
											"TO":   "{{ scratchWorkspace }}",
										},
									},
								},
							},
						},
					},
				},
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Name:        enricherComponentName,
								Description: "enricher-component",
								Type:        v1.ComponentTypeEnricher,
								Steps: []v1.Step{
									{
										Name:       enricherComponentStepName,
										Image:      enricherComponentImage,
										Executable: "/bin/enrich",
									},
								},
							},
						},
					},
				},
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Name:        filterComponentName,
								Description: "filter-component",
								Type:        v1.ComponentTypeFilter,
								Steps: []v1.Step{
									{
										Name:       filterComponentStepName,
										Image:      filterComponentImage,
										Executable: "/bin/filter",
									},
								},
							},
						},
					},
				},
				{
					ComponentRefs: []v1.ComponentRef{
						{
							Component: v1.Component{
								Name:        reporterComponentName,
								Description: "reporter-component",
								Type:        v1.ComponentTypeReporter,
								Steps: []v1.Step{
									{
										Name:       reporterComponentStepName,
										Image:      reporterComponentImage,
										Executable: "/bin/report",
										Args:       []string{"-arg1=1"},
									},
								},
							},
						},
					},
				},
			},
		}
	)
	defer cancel()

	exe, err := engine.NewExecutor(
		mockContainerExec,
		&engine.ExecutorConfig{
			InstanceIDGenerator:  idGenerator,
			TmpFolderProvisioner: tmpFolderProvisioner,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, exe)

	var (
		envVars = []string{
			fmt.Sprintf("SMITHY_INSTANCE_ID=%s", instanceID.String()),
			"SMITHY_LOG_LEVEL=debug",
		}
		sourcePath         = sourceCodeHostPath + ":" + sourceCodeMountPath
		scratchPath        = scratchHostPath + ":" + scratchMountPath
		workspacePath      = path.Join(absPath, fmt.Sprintf("%s:/workspace", ".smithy"))
		targetMetadataPath = targetMetdatadaHostPath + ":" + targetMetadataMountPath
	)

	t.Run("it executes a workflow correctly", func(t *testing.T) {
		gomock.InOrder(
			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       targetComponentStepName,
						Image:      targetComponentImage,
						Executable: "/bin/clone",
						EnvVars:    appendAndSort(envVars, "REPO_URL=github.com/andream16/tree"),
						VolumeBindings: []string{
							workspacePath,
							sourcePath,
						},
						Cmd: []string{"/workspace/source-code"},
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       scanner1ComponentStepName1,
						Image:      scanner1ComponentImage,
						Executable: "/bin/prescan",
						EnvVars:    envVars,
						VolumeBindings: []string{
							workspacePath,
							scratchPath,
							sourcePath,
						},
						Cmd: []string{"--from=/workspace/source-code", "--to=/workspace/scratch"},
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       scanner1ComponentStepName2,
						Image:      scanner1ComponentImage,
						Executable: "/bin/scan",
						EnvVars:    envVars,
						VolumeBindings: []string{
							workspacePath,
							scratchPath,
						},
						Cmd: []string{"/workspace/scratch"},
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       scanner2ComponentStepName,
						Image:      scanner2ComponentImage,
						Executable: "/bin/scan",
						EnvVars: appendAndSort(
							envVars,
							"FROM=/workspace/source-code",
							"TARGET_METADATA_PATH=/workspace/target-metadata",
							"TO=/workspace/scratch",
						),
						VolumeBindings: []string{
							workspacePath,
							scratchPath,
							sourcePath,
							targetMetadataPath,
						},
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       enricherComponentStepName,
						Image:      enricherComponentImage,
						Executable: "/bin/enrich",
						VolumeBindings: []string{
							workspacePath,
						},
						EnvVars: envVars,
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       filterComponentStepName,
						Image:      filterComponentImage,
						Executable: "/bin/filter",
						VolumeBindings: []string{
							workspacePath,
						},
						EnvVars: envVars,
					},
				).
				Return(nil),

			mockContainerExec.
				EXPECT().
				RunAndWait(
					ctx,
					engine.ContainerConfig{
						Name:       reporterComponentStepName,
						Image:      reporterComponentImage,
						Executable: "/bin/report",
						VolumeBindings: []string{
							workspacePath,
						},
						Cmd: []string{
							"-arg1=1",
						},
						EnvVars: envVars,
					},
				).
				Return(nil),
		)

		require.NoError(t, exe.Execute(ctx, workflow))
	})
}
