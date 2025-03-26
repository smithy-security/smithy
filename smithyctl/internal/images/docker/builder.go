package docker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	dockerimagetypes "github.com/docker/docker/api/types/image"
	dockerregistrytypes "github.com/docker/docker/api/types/registry"
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
	username, password string
	labels             map[string]string
	sdkVersion         string
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

// WithBaseDockerfilePath sets the base Dockerfile that will be used to build
// all the components
func WithBaseDockerfilePath(dockerfilePath string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.baseDockerfilePath = dockerfilePath
	}
}

// WithLabels overrides the labels that will be set in the component image to
// be built
func WithLabels(labelMap map[string]string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.labels = labelMap
	}
}

// WithUsernamePassword overrides the default username and password used to
// authenticate with the registry
func WithUsernamePassword(username, password string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.username = username
		o.password = password
	}
}

// WithSDKVersion customises the sdk version.
func WithSDKVersion(version string) BuilderOptionFn {
	return func(o *builderOptions) {
		o.sdkVersion = version
	}
}

func makeOptions(ctx context.Context, daemon dockerBuilder, opts ...BuilderOptionFn) (builderOptions, error) {
	daemonVersion, err := daemon.ServerVersion(ctx)
	if err != nil {
		return builderOptions{}, errors.Errorf("could not connect to Docker daemon: %w", err)
	}

	defaultOpts := builderOptions{
		push:               false,
		username:           "username",
		password:           "password",
		labels:             images.DefaultLabels,
		baseDockerfilePath: "./new-components/Dockerfile",
		platform:           daemonVersion.Os + "/" + daemonVersion.Arch,
		sdkVersion:         "unset",
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
	ImagePush(ctx context.Context, image string, options dockerimagetypes.PushOptions) (io.ReadCloser, error)
	ServerVersion(ctx context.Context) (dockertypes.Version, error)
}

// Builder is used to build images with the docker daemon
type Builder struct {
	client        dockerBuilder
	componentPath string
	opts          builderOptions
	dryRun        bool
	report        images.Report
	prepareTar    func(baseDockerfilePath, path string, extraPaths ...string) (io.ReadCloser, error)
}

// NewBuilder returns a bootstraped instance of the Builder object
func NewBuilder(
	ctx context.Context,
	client dockerBuilder,
	componentPath string,
	dryRun bool,
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
		dryRun:        dryRun,
		report: images.Report{
			CustomImages: []images.CustomImageReport{},
		},
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

type buildLogLine struct {
	Stream string `json:"stream"`
}

type errorLine struct {
	Error       string      `json:"error"`
	ErrorDetail errorDetail `json:"errorDetail"`
}

type errorDetail struct {
	Message string `json:"message"`
}

// Build is invoked to build an image for a component. The component should
func (b *Builder) Build(ctx context.Context, cr *images.ComponentRepository) (string, error) {
	// check first if there is an image make target that we can use to build
	// the image. if the command runs successfully, then we execute the target
	err := executeSubprocess(
		ctx,
		"/bin/bash", "-c", fmt.Sprintf("make -C %s --dry-run --quiet image", cr.Directory()),
	)
	if err == nil {
		b.report.CustomImages = append(b.report.CustomImages, images.CustomImageReport{
			Tags:          cr.URLs(),
			ContextPath:   cr.Directory(),
			ComponentPath: cr.Directory(),
		})

		if b.dryRun {
			return cr.URLs()[0], nil
		}

		var buildErrs error
		for _, tag := range cr.Tags() {
			buildErr := executeSubprocess(
				ctx,
				"/bin/sh", "-c", fmt.Sprintf(
					"make -C %s --quiet image PUSH=%v BUILD_ARCHITECTURE=%s COMPONENT_REGISTRY=%s COMPONENT_REPOSITORY=%s COMPONENT_TAG=%s",
					cr.Directory(), b.opts.push, b.opts.platform, cr.Registry(), cr.Repo(), tag,
				),
			)
			if buildErr != nil {
				buildErrs = errors.Join(buildErrs, buildErr)
			}
		}
		return cr.URLs()[0], buildErrs
	}

	b.report.CustomImages = append(b.report.CustomImages, images.CustomImageReport{
		Tags:   cr.URLs(),
		Labels: b.opts.labels,
		BuildArgs: map[string]string{
			"COMPONENT_PATH": cr.Directory(),
			"SDK_VERSION":    b.opts.sdkVersion,
		},
		Platform:      b.opts.platform,
		ContextPath:   cr.Directory(),
		ComponentPath: cr.Directory(),
		Dockerfile:    b.opts.baseDockerfilePath,
	})

	if b.dryRun {
		return cr.URLs()[0], nil
	}

	fmt.Fprintf(os.Stderr, "building docker image for component %s with tags %q\n", cr.Directory(), cr.URLs())
	buildCtx, err := b.prepareTar(b.opts.baseDockerfilePath, cr.Directory())
	if err != nil {
		return "", errors.Errorf("could not create tar for Docker image build context: %w", err)
	}

	fmt.Fprintf(
		os.Stderr,
		"building component image for platform %s with tags %q\n",
		b.opts.platform,
		cr.URLs(),
	)

	var (
		sdkVersion         = "unset"
		componentDirectory = cr.Directory()
	)

	if b.opts.sdkVersion != "" {
		sdkVersion = b.opts.sdkVersion
	}

	buildResp, err := b.client.ImageBuild(
		ctx,
		buildCtx,
		dockertypes.ImageBuildOptions{
			Tags: cr.URLs(),
			BuildArgs: map[string]*string{
				"COMPONENT_PATH": &componentDirectory,
				"SDK_VERSION":    &sdkVersion,
			},
			PullParent: true,
			Platform:   b.opts.platform,
			Labels:     b.opts.labels,
			Dockerfile: b.opts.baseDockerfilePath,
		},
	)
	if err != nil {
		return "", errors.Errorf("%s: could not build image for component: %w", cr.Directory(), err)
	}
	defer buildResp.Body.Close()

	var lastLine string
	scanner := bufio.NewScanner(buildResp.Body)
	for scanner.Scan() {
		lastLine = scanner.Text()

		logLine := buildLogLine{}
		err := json.Unmarshal(scanner.Bytes(), &logLine)
		if err == nil {
			logLine.Stream = strings.Trim(logLine.Stream, "\n")
			if logLine.Stream != "" {
				fmt.Fprintln(os.Stderr, logLine.Stream)
			}
		}
	}

	errLine := &errorLine{}
	err = json.Unmarshal([]byte(lastLine), errLine)
	if err != nil || errLine.Error == "" {
		return cr.URLs()[0], b.push(ctx, cr)
	}

	return "", errors.Errorf("%s: there was an error while building component image: %w, %w",
		cr.URLs(), errors.New(errLine.Error), errors.New(errLine.ErrorDetail.Message),
	)
}

func (b *Builder) push(ctx context.Context, cr *images.ComponentRepository) (err error) {
	if !b.opts.push {
		fmt.Fprint(os.Stderr, "not pushing image\n")
		return nil
	}

	authConfigBytes, err := json.Marshal(dockerregistrytypes.AuthConfig{
		Username: b.opts.username,
		Password: b.opts.password,
	})
	if err != nil {
		return errors.Errorf("could not marshal registry authentication configuration: %w", err)
	}

	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

	readClosers := []io.ReadCloser{}
	defer func() {
		for _, rd := range readClosers {
			err = errors.Join(err, rd.Close())
		}
	}()

	fmt.Fprintf(os.Stderr, "pushing tags %q\n", cr.URLs())
	for _, tag := range cr.URLs() {
		var pushResp io.ReadCloser
		fmt.Fprintf(os.Stderr, "pushing image %s\n", tag)
		pushResp, err = b.client.ImagePush(ctx, tag, dockerimagetypes.PushOptions{
			RegistryAuth: authConfigEncoded,
		})
		if err != nil {
			return errors.Errorf("%s: could not push image: %w", tag, err)
		}

		readClosers = append(readClosers, pushResp)
		scanner := bufio.NewScanner(pushResp)
		var lastLine string
		for scanner.Scan() {
			lastLine = scanner.Text()
			fmt.Fprintln(os.Stderr, lastLine)
		}

		errLine := &errorLine{}
		err = json.Unmarshal([]byte(lastLine), errLine)
		if err == nil && errLine.Error != "" {
			return errors.Errorf("could not push image to the repository: %s", errLine.Error)
		}
	}

	return nil
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

// Report returns a report of all the images built and how they were built
func (b *Builder) Report() images.Report {
	return images.Report{
		CustomImages: b.report.CustomImages[:],
	}
}
