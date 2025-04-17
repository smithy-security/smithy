package main

import (
	"context"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/package-url/packageurl-go"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

type (
	// Conf wraps the component configuration.
	Conf struct {
		TargetMetadataPath string
		Image              string
	}
	imageMetadataWriterTarget struct {
		conf *Conf
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	targetMetadataPath, err := env.GetOrDefault(
		"IMAGE_GET_TARGET_METADATA_PATH",
		"",
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get IMAGE_GET_TARGET_METADATA_PATH: %w", err)
	}

	image, err := env.GetOrDefault(
		"IMAGE_GET_IMAGE",
		"",
		append(envOpts, env.WithDefaultOnError(true))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get IMAGE_GET_IMAGE: %w", err)
	}

	if targetMetadataPath != "" && !strings.HasSuffix(targetMetadataPath, "target.json") {
		targetMetadataPath = path.Join(targetMetadataPath, "target.json")
	}
	return &Conf{
		TargetMetadataPath: targetMetadataPath,
		Image:              image,
	}, nil
}

func WriteTargetMetadata(conf *Conf) error {
	purl, err := packageUrlFromImage(conf.Image)
	if err != nil {
		return errors.Errorf("could not get package url from image: %w", err)
	}

	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
		OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
			PackageUrl: purl.ToString(),
			Tag:        purl.Version,
		},
	}

	marshaledDataSource, err := protojson.Marshal(dataSource)
	if err != nil {
		return errors.Errorf("could not marshal data source into JSON: %w", err)
	}

	// Write content to the file
	err = os.WriteFile(conf.TargetMetadataPath, marshaledDataSource, 0644)
	if err != nil {
		return errors.Errorf("Error writing file: %w", err)
	}
	return nil
}

func packageUrlFromImage(image string) (*packageurl.PackageURL, error) {
	var (
		namespace = ""
		path      = ""
		tag       = ""
		digest    = ""
	)
	// Parse the reference
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	// Add registry if not docker.io
	registry := ref.Context().Registry.Name()
	if registry != "index.docker.io" && registry != "docker.io" {
		namespace = registry
	}

	// Add repository path
	path = ref.Context().RepositoryStr()

	// Add tag or digest
	if tagged, ok := ref.(name.Tag); ok {
		tag = tagged.TagStr()
	} else if digested, ok := ref.(name.Digest); ok {
		digest = digested.DigestStr()
	}

	var qualifiers packageurl.Qualifiers
	if digest != "" {
		qualifiers = packageurl.QualifiersFromMap(map[string]string{"digest": digest})

		// special edge case: always prefer the digest over tag
		tag = ""
	}

	if tag == "" && digest == "" {
		// If no tag or digest is provided, default to "latest"
		tag = "latest"
	}

	return packageurl.NewPackageURL(
		packageurl.TypeDocker,
		namespace,
		path,
		tag,
		qualifiers,
		"",
	), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	conf, err := NewConf(nil)
	if err != nil {
		return errors.Errorf("could not create new configuration: %w", err)
	}

	metadataTarget, err := NewTarget(conf)
	if err != nil {
		return errors.Errorf("could not create git clone target: %w", err)
	}

	opts := append(make([]component.RunnerOption, 0), component.RunnerWithComponentName("image-get"))

	if err := component.RunTarget(
		ctx,
		metadataTarget,
		opts...,
	); err != nil {
		return errors.Errorf("could not run target: %w", err)
	}

	return nil
}

func NewTarget(conf *Conf) (*imageMetadataWriterTarget, error) {
	if conf == nil {
		return nil, errors.New("conf cannot be nil")
	}

	return &imageMetadataWriterTarget{
		conf: conf,
	}, nil
}

func (t *imageMetadataWriterTarget) Prepare(ctx context.Context) error {
	if t.conf == nil {
		return errors.New("conf cannot be nil")
	}

	if err := WriteTargetMetadata(t.conf); err != nil {
		return errors.Errorf("could not write target metadata: %w", err)
	}

	return nil
}
