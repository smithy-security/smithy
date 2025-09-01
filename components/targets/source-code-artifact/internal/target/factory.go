package target

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/tar"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/targz"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/zip"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher/remote"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher/s3"
)

// GetFetcher returns the configured fetcher based on the supplied artifact url.
func GetFetcher(ctx context.Context, cfg fetcher.Config) (Fetcher, artifact.SourceType, error) {
	sourceType, err := artifact.GetSourceType(cfg.ArtifactURL)
	if err != nil {
		return nil,
			artifact.SourceTypeUnsupported,
			errors.Errorf("could not determine source type for url: '%s'", cfg.ArtifactURL)
	}

	var (
		f          Fetcher
		fetcherErr error
	)

	switch sourceType {
	case artifact.SourceTypeS3:
		f, fetcherErr = s3.NewFetcher(ctx, sourceType, cfg, s3.DetailsConstructor)
	case artifact.SourceTypeGCS:
		f, fetcherErr = s3.NewFetcher(ctx, sourceType, cfg, s3.GCSDetailsConstructor)
	case artifact.SourceTypeRemote:
		f, fetcherErr = remote.NewFetcher(cfg)
	default:
		return nil,
			artifact.SourceTypeUnsupported,
			errors.Errorf("unsupported source type '%s' for url: '%s'", sourceType, cfg.ArtifactURL)
	}

	switch {
	case fetcherErr != nil:
		return nil, sourceType, errors.Errorf("failed to initialise fetcher for '%s': %w", sourceType, fetcherErr)
	case f == nil:
		return nil, sourceType, errors.New("could not determine fetcher")
	}

	return f, sourceType, nil
}

var (
	// ErrUnsupportedFileType is returned when the file type is not supported
	// by the system
	ErrUnsupportedFileType = errors.New("unsupported file type")
	// ErrNoExtractor is returned when no extractor could be determined
	ErrNoExtractor = errors.New("could not determine extractor")
)

// GetExtractor returns the configured extractor based on the supplied artifact url.
func GetExtractor(fileType artifact.FileType) (Extractor, artifact.FileType, error) {
	var extractor Extractor
	switch fileType {
	case artifact.FileTypeZip:
		extractor = zip.NewExtractor()
	case artifact.FileTypeTar:
		extractor = tar.NewExtractor()
	case artifact.FileTypeTarGz:
		extractor = targz.NewExtractor()
	case artifact.FileTypeUnarchived:
		extractor = NoopExtractor{}
	default:
		return nil, artifact.FileTypeUnsupported, errors.Errorf("%s: %w", fileType, ErrUnsupportedFileType)
	}

	if extractor == nil {
		return nil, fileType, ErrNoExtractor
	}

	return extractor, fileType, nil
}

// NoopExtractor is a noop extractor that does no changes to the file
type NoopExtractor struct{}

// ExtractArtifact is a no-op
func (NoopExtractor) ExtractArtifact(_ context.Context, _, _ string) error {
	return nil
}
