package registry

import (
	"context"
	"fmt"
	"log/slog"
	"path"

	"github.com/go-errors/errors"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithyctl/internal/logging"
)

type (
	orasRegistry struct {
		baseRepository string
		registry       registry.Registry
	}

	// PackageRequest represents a Package request.
	PackageRequest struct {
		Component        *v1.Component
		SDKVersion       string
		ComponentVersion string
	}
)

// New returns a new registry implementation with an underlying oras-go client.
func New(
	registryHost string,
	baseRepository string,
	registryAuthEnabled bool,
	registryAuthUsername string,
	registryAuthPassword string,
) (*orasRegistry, error) {
	switch {
	case registryHost == "":
		return nil, errors.New("registry host is required")
	case baseRepository == "":
		return nil, errors.New("registry base repository is required")
	case registryAuthEnabled && registryAuthUsername == "":
		return nil, errors.New("registry auth username is required")
	case registryAuthEnabled && registryAuthPassword == "":
		return nil, errors.New("registry auth password is required")
	}

	reg, err := remote.NewRegistry(registryHost)
	if err != nil {
		return nil, errors.Errorf("could not create registry for host '%s': %w", registryHost, err)
	}

	var regAuthClient = &auth.Client{
		Cache: auth.NewCache(),
	}

	if registryAuthEnabled {
		regAuthClient.Credential = auth.StaticCredential(
			registryHost,
			auth.Credential{
				Username: registryAuthUsername,
				Password: registryAuthPassword,
			},
		)
		regAuthClient.Client = retry.DefaultClient
	} else {
		reg.PlainHTTP = true
	}

	reg.Client = regAuthClient

	return &orasRegistry{
		baseRepository: baseRepository,
		registry:       reg,
	}, nil
}

// Package packages a component spec into an OCI compliant manifest.
func (r *orasRegistry) Package(ctx context.Context, req PackageRequest) error {
	const artifactType = "application/vnd.custom.smithy-component+yaml"

	switch {
	case req.Component == nil:
		return errors.New("component is required")
	case req.SDKVersion == "":
		return errors.New("SDK version is required")
	}

	var (
		component        = req.Component
		componentVersion = "latest"
		sdkVersion       = req.SDKVersion
		logger           = logging.FromContext(ctx)
	)

	if req.ComponentVersion != "" {
		componentVersion = req.ComponentVersion
	}

	logger = logger.With(
		slog.String(logging.ComponentNameKey, component.Name),
		slog.String(logging.ComponentTypeKey, component.Type.String()),
		slog.String(logging.ComponentSDKVersionKey, sdkVersion),
		slog.String(logging.ComponentVersionKey, componentVersion),
	)

	logger.Debug("preparing to marshal component as a blob...")

	blob, err := yaml.Marshal(component)
	if err != nil {
		return errors.Errorf("could not yaml marshal component: %w", err)
	}

	logger.Debug(
		"successfully marshalled component blob to yaml",
		slog.String("component_yaml", string(blob)),
	)

	dest := path.Join(r.baseRepository, component.Type.String(), component.Name)
	repo, err := r.registry.Repository(ctx, dest)
	if err != nil {
		return errors.Errorf("could not create repository for registry destination '%s': %w", dest, err)
	}

	logger.Debug("preparing to push the blob to the configured OCI registry...")

	blobDescriptor, err := oras.PushBytes(ctx, repo, artifactType, blob)
	if err != nil {
		return errors.Errorf("could not push component's blob: %w", err)
	}

	logger.Debug(
		"successfully pushed component's blob to OCI registry",
		slog.Any("blob_description", blobDescriptor),
	)

	logger.Debug("preparing to pack the manifest...")

	manifestDescriptor, err := oras.PackManifest(
		ctx,
		repo,
		oras.PackManifestVersion1_1,
		artifactType,
		oras.PackManifestOptions{
			Layers: []ocispec.Descriptor{blobDescriptor},
			ManifestAnnotations: map[string]string{
				"smithy.sdk.version":           sdkVersion,
				"smithy.component.description": component.Description,
				"smithy.component.name":        component.Name,
				"smithy.component.type":        component.Type.String(),
				"smithy.component.version":     componentVersion,
				"smithy.component.source": fmt.Sprintf(
					"new-components/%s/%s",
					component.Type,
					component.Name,
				),
				"smithy.component.url": fmt.Sprintf(
					"https://github.com/smithy-security/smithy/tree/main/new-components/%s/%s",
					component.Type,
					component.Name,
				),
			},
		},
	)
	if err != nil {
		return errors.Errorf("could not pack manifest: %w", err)
	}

	logger.Debug(
		"successfully packed manifest",
		slog.Any("manifest_description", manifestDescriptor),
	)

	logger.Debug("preparing to tag manifest...")

	if err := repo.Tag(ctx, manifestDescriptor, componentVersion); err != nil {
		return errors.Errorf("could not tag manifest: %w", err)
	}

	logger.Debug("successfully tagged manifest")

	return nil
}
