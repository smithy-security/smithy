package docker

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/go-errors/errors"
	"golang.org/x/sync/errgroup"

	"github.com/smithy-security/smithy/smithyctl/internal/engine"
	"github.com/smithy-security/smithy/smithyctl/internal/logging"
)

// executor implements a container executor for docker.
type executor struct {
	dockerClient *client.Client
}

// NewExecutor returns a new docker executor.
func NewExecutor(cli *client.Client) (*executor, error) {
	// // Using available docker setup.
	// cli, err := client.NewClientWithOpts(client.FromEnv)
	// if err != nil {
	// 	return nil, errors.Errorf("failed to create docker client: %w", err)
	// }
	return &executor{dockerClient: cli}, nil
}

// RunAndWait creates, runs and waits for a container to complete.
// It returns an error if the container doesn't complete successfully.
func (e *executor) RunAndWait(ctx context.Context, conf engine.ContainerConfig) error {
	cntr, err := e.createContainer(ctx, conf)
	if err != nil {
		return err
	}

	containerID := cntr.ID
	// Adding the ID to the logger in the context so it can be re-used by the helper functions as well.
	ctx = logging.ContextWithLogger(ctx, logging.FromContext(ctx).With("container_id", containerID))
	// Remove the container no matter what to reduce chances of messing up the environment.
	defer e.removeContainer(ctx, containerID)

	if err := e.runContainer(ctx, containerID); err != nil {
		return err
	}

	return e.waitContainer(ctx, containerID)
}

func (e *executor) createContainer(ctx context.Context, conf engine.ContainerConfig) (container.CreateResponse, error) {
	// Relying on default settings but making it explicit so it doesn't look misconfigured.
	var defaultNetwork *network.NetworkingConfig = nil

	resp, err := e.dockerClient.ContainerCreate(
		ctx,
		&container.Config{
			Image:      conf.Image,
			Entrypoint: []string{conf.Executable},
			Cmd:        conf.Cmd,
			Env:        conf.EnvVars,
		},
		&container.HostConfig{
			Binds: conf.VolumeBindings,
		},
		defaultNetwork,
		conf.Platform,
		conf.Name,
	)
	if err != nil {
		return container.CreateResponse{}, errors.Errorf("failed to create container: %w", err)
	}

	return resp, nil
}

func (e *executor) runContainer(ctx context.Context, containerID string) error {
	if err := e.dockerClient.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return errors.Errorf("failed to run container: %w", err)
	}
	return nil
}

func (e *executor) waitContainer(ctx context.Context, containerID string) error {
	logger := logging.FromContext(ctx)

	// Preparing to stream container logs.
	logReader, err := e.dockerClient.ContainerLogs(
		ctx,
		containerID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
		},
	)
	if err != nil {
		return errors.Errorf("failed to get container logs: %w", err)
	}

	defer func() {
		if err := logReader.Close(); err != nil {
			logger.Error(
				"could not close container log reader",
				slog.String("err", err.Error()),
			)
		}
	}()

	// ContainerWait simplifies watching for container's errors/status a lot.
	statusCh, errCh := e.dockerClient.ContainerWait(
		ctx,
		containerID,
		container.WaitConditionNotRunning,
	)

	// This is mainly in place to not leak the go routine that is copying to os.Stdout.
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if _, err := io.Copy(os.Stdout, logReader); err != nil {
			logger.Error(
				"failed to stream container logs",
				slog.String("err", err.Error()),
			)
		}

		return nil
	})

	g.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return errors.Errorf("unexpected error: %w", err)
			}
		case status := <-statusCh:
			if status.StatusCode != 0 {
				return errors.Errorf("container exited with an error status code: %d", status.StatusCode)
			}
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return errors.Errorf("failed to wait for container: %w", err)
	}

	return nil
}

func (e *executor) removeContainer(ctx context.Context, containerID string) {
	if err := e.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}); err != nil {
		logging.
			FromContext(ctx).
			Error(
				"failed to remove container",
				slog.String("error", err.Error()),
			)
	}
}
