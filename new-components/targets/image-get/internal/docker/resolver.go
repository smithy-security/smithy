package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path"

	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/go-errors/errors"

	"github.com/smithy-security/pkg/utils"

	"github.com/smithy-security/smithy/new-components/targets/image-get/internal/config"
)

type dockerPuller interface {
	ImagePull(ctx context.Context, refStr string, options dockerimage.PullOptions) (io.ReadCloser, error)
	ImageSave(ctx context.Context, imageIDs []string, saveOpts ...client.ImageSaveOption) (io.ReadCloser, error)
}

// Resolver uses the docker client to pull an image
type Resolver struct {
	client dockerPuller
	config *config.Conf
}

// NewResolver returns a bootstrapped instance of the resolver based on a
// Docker client
func NewResolver(client dockerPuller, config *config.Conf) (*Resolver, error) {
	if utils.IsNil(client) {
		return nil, errors.Errorf("docker client is nil")
	}
	if config == nil {
		return nil, errors.Errorf("received nil configuration")
	}
	return &Resolver{client: client, config: config}, nil
}

// Resolve fetches an image from a container registry
func (s *Resolver) Resolve(ctx context.Context) (string, error) {
	// if the image does not refer to a smithy component or is not tagged as
	// the latest version of the image we just try to pull it
	pullOpts, err := s.makePullOptions()
	if err != nil {
		return "", errors.Errorf("could not resolve image %s, received error trying to make pull options err: %w", s.config.ImageRef, err)
	}
	readCloser, err := s.client.ImagePull(ctx, s.config.ImageRef, *pullOpts)
	if err != nil {
		return "", errors.Errorf("%s: could not pull image; %w", s.config.ImageRef, err)
	}

	slog.Info("pulling image", slog.String("image_ref", s.config.ImageRef))

	defer readCloser.Close()
	_, err = io.Copy(os.Stderr, readCloser)
	if err != nil {
		return "", errors.Errorf("could not redirect docker daemon output to stderr: %w", err)
	}

	return s.saveImage(ctx)
}

func (s *Resolver) makePullOptions() (*dockerimage.PullOptions, error) {
	if s.config.Username == "" && s.config.Token == "" {
		return &dockerimage.PullOptions{}, nil
	}
	authConfig := registry.AuthConfig{
		Username: s.config.Username,
		Password: s.config.Token,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return nil, errors.Errorf("could not marshall autconfig, err %w", err)
	}
	authStr := base64.URLEncoding.EncodeToString(encodedJSON)

	return &dockerimage.PullOptions{RegistryAuth: authStr}, nil
}

func (s *Resolver) saveImage(ctx context.Context) (string, error) {
	slog.Debug("saving image", slog.String("imageRef", s.config.ImageRef))
	reader, err := s.client.ImageSave(ctx, []string{s.config.ImageRef})
	if err != nil {
		return "", errors.Errorf("failed to save image: %w", err)
	}
	defer reader.Close()
	saveFile := path.Join(s.config.TargetDir, "image.tar.gz")
	file, err := os.Create(saveFile)
	if err != nil {
		return "", errors.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, reader)
	if err != nil {
		return "", errors.Errorf("failed to write image to file: %w", err)
	}

	slog.Info("Image saved to ", slog.String("imageloc", saveFile))
	return saveFile, nil
}
