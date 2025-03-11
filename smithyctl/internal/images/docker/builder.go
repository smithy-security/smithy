package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/archive"
	"github.com/go-errors/errors"
	"golang.org/x/sync/errgroup"

	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/smithyctl/internal/images"
)

// builderOptions is a struct that defines common properties and behaviour of all the
// images that will be built for the Builder
type builderOptions struct {
	platform           string
	baseDockerfilePath string
	push               bool
	labels             map[string]string
}

// BuilderOptionFn is used to modify the options passed to the builder
type BuilderOptionFn func(*builderOptions)

// PushImages will cause all images to be built and pushed immediately
func PushImages() BuilderOptionFn {
	return func(o *builderOptions) {
		o.push = true
	}
}

// WithPlatform will cause the images to be built for a platform that is not
// the native platform of the docker daemon
func WithPlatform(p string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.platform = p
	}
}

func WithBaseDockerfilePath(dockerfilePath string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.baseDockerfilePath = dockerfilePath
	}
}

func makeOptions(ctx context.Context, daemon dockerBuilder, opts ...BuilderOptionFn) (builderOptions, error) {
	daemonVersion, err := daemon.ServerVersion(ctx)
	if err != nil {
		return builderOptions{}, errors.Errorf("could not connect to Docker daemon: %w", err)
	}

	defaultOpts := builderOptions{
		push:               false,
		labels:             images.DefaultLabels,
		baseDockerfilePath: "./new-components/Dockerfile",
		platform:           daemonVersion.Os + "/" + daemonVersion.Arch,
	}

	for _, opt := range opts {
		opt(&defaultOpts)
	}

	return defaultOpts, nil
}

// dockerBuilder is an interface of a client that builds images using the
// docker client
type dockerBuilder interface {
	ImageBuild(ctx context.Context, buildContext io.Reader, options dockertypes.ImageBuildOptions) (dockertypes.ImageBuildResponse, error)
	ServerVersion(ctx context.Context) (dockertypes.Version, error)
}

// Builder is used to build images with the docker daemon
type Builder struct {
	client        dockerBuilder
	componentPath string
	opts          builderOptions
	prepareTar    func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error)
}

// NewBuilder returns a bootstraped instance of the Builder object
func NewBuilder(
	ctx context.Context,
	client dockerBuilder,
	componentPath string,
	opts ...BuilderOptionFn,
) (*Builder, error) {
	if utils.IsNil(client) {
		return nil, ErrNoDockerClient
	}

	buildOpts, err := makeOptions(ctx, client, opts...)
	if err != nil {
		return nil, errors.Errorf("there was an error querying the Docker daemon: %w", err)
	}

	return &Builder{
		client:        client,
		componentPath: componentPath,
		opts:          buildOpts,
		prepareTar: func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error) {
			return archive.TarWithOptions(
				".",
				&archive.TarOptions{
					IncludeFiles: append(
						[]string{baseDockerfilePath, path},
						extraPaths...,
					),
				},
			)
		},
	}, nil
}

type buildErrorLine struct {
	Error       string           `json:"error"`
	ErrorDetail buildErrorDetail `json:"errorDetail"`
}

type buildErrorDetail struct {
	Message string `json:"message"`
}

func (b *Builder) Build(ctx context.Context, cr *images.ComponentRepository) (string, error) {
	// check first if there is an image make target that we can use to build
	// the image. if the command runs successfully, then we execute the target
	err := executeSubprocess(
		ctx,
		"/bin/bash", "-c", fmt.Sprintf("make -C %s --dry-run --quiet image", cr.Directory()),
	)
	if err == nil {
		return cr.URL(), executeSubprocess(
			ctx,
			"/bin/sh", "-c", fmt.Sprintf(
				"make -C %s --quiet image BUILD_ARCHITECTURE=%s COMPONENT_REGISTRY=%s COMPONENT_REPOSITORY=%s COMPONENT_TAG=%s",
				cr.Directory(), b.opts.platform, cr.Registry(), cr.Repo(), cr.Tag(),
			),
		)
	}

	fmt.Fprintf(os.Stderr, "building docker image %s\n", cr.URL())
	buildCtx, err := b.prepareTar(b.opts.baseDockerfilePath, cr.Directory())
	if err != nil {
		return "", errors.Errorf("could not create tar for Docker image build context: %w", err)
	}

	fmt.Fprintf(os.Stderr, "building component %s for platform %s", cr.URL(), b.opts.platform)
	componentDirectory := cr.Directory()
	buildResp, err := b.client.ImageBuild(
		ctx,
		buildCtx,
		dockertypes.ImageBuildOptions{
			Tags: []string{cr.URL()},
			BuildArgs: map[string]*string{
				"COMPONENT_PATH": &componentDirectory,
			},
			PullParent: true,
			Platform:   b.opts.platform,
			Labels:     b.opts.labels,
			Dockerfile: b.opts.baseDockerfilePath,
		},
	)
	if err != nil {
		return "", errors.Errorf("%s: could not build component image: %w", cr.URL(), err)
	}
	defer buildResp.Body.Close()

	var lastLine string
	scanner := bufio.NewScanner(buildResp.Body)
	for scanner.Scan() {
		lastLine = scanner.Text()
		fmt.Fprintln(os.Stderr, scanner.Text())
	}

	errLine := &buildErrorLine{}
	err = json.Unmarshal([]byte(lastLine), errLine)
	if err != nil || errLine.Error == "" {
		return cr.URL(), nil
	}

	return "", errors.Errorf("%s: there was an error while building component image: %w, %w",
		cr.URL(), errors.New(errLine.Error), errors.New(errLine.ErrorDetail.Message),
	)
}

func executeSubprocess(ctx context.Context, executable string, args ...string) error {
	fmt.Fprintf(os.Stderr, "executing command: %s %q\n", executable, args)
	subProcess := exec.CommandContext(ctx, executable, args...)

	stdErrPipe, err := subProcess.StderrPipe()
	if err != nil {
		return errors.Errorf("could not capture stderr of subprocess: %w", err)
	}

	stdOutPipe, err := subProcess.StdoutPipe()
	if err != nil {
		return errors.Errorf("could not capture stdout of subprocess: %w", err)
	}

	copyingErrGroup, _ := errgroup.WithContext(ctx)
	copyingErrGroup.Go(func() error {
		_, readErr := io.Copy(os.Stderr, stdOutPipe)
		return readErr
	})

	copyingErrGroup.Go(func() error {
		_, readErr := io.Copy(os.Stderr, stdErrPipe)
		return readErr
	})

	if err := subProcess.Start(); err != nil {
		return errors.Errorf("there was an error while starting the subprocess: %w", err)
	}

	// wait for the streams to finish copying. this must be invoked before the
	// Wait method, otherwise the streams will be closed before all the data
	// are copied.
	if err := copyingErrGroup.Wait(); err != nil {
		return errors.Errorf("there was an error while waiting for the subprocess streams to finish: %w", err)
	}

	// we don't need to react immediately to this error, an error over here
	// means that either the process failed or the goroutine monitoring the
	// process failed. in the first case we should propagate the exit code to
	// the next process in the line, in the second case we shouldn't cause the
	// next process to fail unless there is a good reason.
	err = subProcess.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if _, isExitErr := err.(*exec.ExitError); isExitErr {
		return errors.Errorf("subprocess exited with error code: %d", subProcess.ProcessState.ExitCode())
	} else if err != nil {
		return errors.Errorf("there was an error while executing subprocess: %w", err)
	}

	return nil
}
