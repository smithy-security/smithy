package target

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/apk"
	plaincopy "github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/extractor/plain-copy"
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
		f, fetcherErr = s3.NewFetcher(ctx, sourceType, cfg, s3.S3DetailsConstructor)
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

// GetExtractor returns the configured extractor based on the supplied artifact url.
func GetExtractor(fileName string) (Extractor, artifact.FileType, error) {
	fileType, err := artifact.GetFileType(fileName)
	if err != nil {
		return nil,
			artifact.FileTypeUnsupported,
			errors.Errorf("could not determine file type for file: '%s'", fileName)
	}

	var extractor Extractor
	switch fileType {
	case artifact.FileTypeZip:
		extractor = zip.NewExtractor()
	case artifact.FileTypeApk:
		extractor = apk.NewExtractor()
	case artifact.FileTypeTar:
		extractor = tar.NewExtractor()
	case artifact.FileTypeTarGz:
		extractor = targz.NewExtractor()
	case artifact.FileTypeUnarchived:
		extractor = plaincopy.NewExtractor()
	default:
		return nil, artifact.FileTypeUnsupported, errors.Errorf("unsupported file type '%s' for file: '%s'", fileType, fileName)
	}

	if extractor == nil {
		return nil, fileType, errors.New("could not determine extractor")
	}

	return extractor, fileType, nil
}
