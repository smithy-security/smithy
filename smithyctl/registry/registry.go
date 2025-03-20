package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path"

	"github.com/distribution/reference"
	"github.com/go-errors/errors"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithy/smithyctl/annotation"
	"github.com/smithy-security/smithy/smithyctl/internal/logging"
)

const componentMediaType = "application/vnd.custom.smithy-component+yaml"

type (
	orasRegistry struct {
		namespace string
		registry  registry.Registry
	}

	// PackageRequest represents a Package request.
	PackageRequest struct {
		ComponentPath    string
		Component        *v1.Component
		SDKVersion       string
		ComponentVersion string
	}

	// FetchPackageResponse wraps the FetchPackage response.
	FetchPackageResponse struct {
		Component   v1.Component
		Annotations map[string]string
	}
)

// New returns a new registry implementation with an underlying oras-go client.
func New(
	registryHost string,
	namespace string,
	registryAuthEnabled bool,
	registryAuthUsername string,
	registryAuthPassword string,
) (*orasRegistry, error) {
	switch {
	case registryHost == "":
		return nil, errors.New("registry host is required")
	case namespace == "":
		return nil, errors.New("registry namespace is required")
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
		namespace: namespace,
		registry:  reg,
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
		dest             = path.Join(r.namespace, req.ComponentPath)
	)

	if req.ComponentVersion != "" {
		componentVersion = req.ComponentVersion
	}

	logger = logger.With(
		slog.String(logging.ComponentNameKey, component.Name),
		slog.String(logging.ComponentTypeKey, component.Type.String()),
		slog.String(logging.ComponentSDKVersionKey, sdkVersion),
		slog.String(logging.ComponentVersionKey, componentVersion),
		slog.String("destination", dest),
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
				annotation.SmithySDKVersion:       sdkVersion,
				annotation.SmithyComponentDescr:   component.Description,
				annotation.SmithyComponentName:    component.Name,
				annotation.SmithyComponentType:    component.Type.String(),
				annotation.SmithyComponentVersion: componentVersion,
				annotation.SmithyComponentSource: fmt.Sprintf(
					"new-components/%s/%s",
					component.Type,
					component.Name,
				),
				annotation.SmithyComponentURL: fmt.Sprintf(
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

// FetchPackage resolves a package given a reference.
// The reference should be in the form:
// ghcr.io/smithy-security/manifests/components/target/example-component:v0.0.1
// localhost:5000/smithy-security/manifests/components/scanner/gosec-parser:v1.1.1
func (r *orasRegistry) FetchPackage(ctx context.Context, ref reference.Reference) (*FetchPackageResponse, error) {
	domainName, err := reference.ParseNamed(ref.String())
	if err != nil {
		return nil, errors.Errorf("could not parse reference name: %w", err)
	}

	tagName, ok := ref.(reference.Tagged)
	if !ok {
		return nil, errors.Errorf("could not parse reference: expected tag, got %T", ref)
	}

	var (
		domain  = domainName.Name()
		ociPath = reference.Path(domainName)
		tag     = tagName.Tag()
		logger  = logging.
			FromContext(ctx).
			With(slog.String("reference", ref.String())).
			With(slog.String("domain", domain)).
			With(slog.String("tag", tag)).
			With(slog.String("oci_path", ociPath))
	)

	logger.Debug("preparing to initialise repository...")
	repo, err := r.registry.Repository(ctx, ociPath)
	if err != nil {
		return nil, errors.Errorf("could not create repository for '%s': %w", ociPath, err)
	}

	logger.Debug("successfully initialised repository!")
	logger.Debug("preparing to fetch package reference...")

	manifestData, _, err := repo.FetchReference(ctx, tag)
	if err != nil {
		return nil, errors.Errorf("could not fetch manifest reference for '%s:%s': %w", ociPath, tag, err)
	}

	logger.Debug("successfully fetched package reference")
	logger.Debug("preparing to fetch blob...")

	blobData, err := content.FetchAll(ctx, repo, manifestData)
	if err != nil {
		return nil, errors.Errorf("could not fetch manifest blob data for '%s:%s': %w", ociPath, tag, err)
	}

	logger.Debug("successfully fetched blob")

	var descr ocispec.Manifest
	if err := json.Unmarshal(blobData, &descr); err != nil {
		return nil, errors.Errorf("could not unmarshal manifest blob data for '%s:%s': %w", ociPath, tag, err)
	}

	var component v1.Component
	for _, layer := range descr.Layers {
		if layer.MediaType != componentMediaType {
			return nil,
				errors.Errorf(
					"layer '%s' has an unsupported media type '%s'",
					layer.Digest,
					layer.MediaType,
				)
		}

		rc, err := repo.Blobs().Fetch(ctx, layer)
		if err != nil {
			return nil, errors.Errorf("could not fetch layer '%s': %w", layer.Digest, err)
		}

		b, err := io.ReadAll(rc)
		if err != nil {
			return nil, errors.Errorf("could not read layer '%s': %w", layer.Digest, err)
		}

		if err := yaml.Unmarshal(b, &component); err != nil {
			return nil, errors.Errorf(
				"could not unmarshal manifest blob data for '%s:%s': %w",
				ociPath,
				tag,
				err,
			)
		}
	}

	return &FetchPackageResponse{
		Annotations: descr.Annotations,
		Component:   component,
	}, nil
}
