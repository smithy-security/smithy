package artifact

import (
	"strings"

	"github.com/go-errors/errors"
)

const (
	// SourceTypeS3 is used for an artefact hosted in an S3 compatible bucket
	SourceTypeS3 SourceType = "s3"
	// SourceTypeGCS is used for an artefact hosteed in a GCS S3 bucket
	SourceTypeGCS SourceType = "gcs"
	// SourceTypeRemote is used for an artefact that can be downloaded with
	// HTTP
	SourceTypeRemote SourceType = "remote"
	// SourceTypeUnsupported is an supported protocol for an artefact
	SourceTypeUnsupported SourceType = "unsupported"

	// FileTypeZip is for zip archives
	FileTypeZip FileType = "zip"
	// FileTypeTar is for tar archives
	FileTypeTar FileType = "tar"
	// FileTypeTarGz is for tar gz archives
	FileTypeTarGz FileType = "tar.gz"
	// FileTypeUnarchived is for artefacts that are not archives
	FileTypeUnarchived FileType = "unarchived"
	// FileTypeUnsupported is for unsupported archive types
	FileTypeUnsupported FileType = "unsupported"
)

type (
	// SourceType type alias for source types.
	SourceType string
	// FileType type alias for file types.
	FileType string
)

func (st SourceType) String() string {
	return string(st)
}

func (ft FileType) String() string {
	return string(ft)
}

// GetSourceType returns the correct source type based on the input one.
func GetSourceType(source string) (SourceType, error) {
	switch {
	case strings.HasPrefix(source, "s3"):
		return SourceTypeS3, nil
	case strings.HasPrefix(source, "gs"):
		return SourceTypeGCS, nil
	case strings.HasPrefix(source, "http"):
		return SourceTypeRemote, nil
	default:
		return SourceTypeUnsupported, errors.Errorf("unsupported source type: %s", source)
	}
}

// ErrNoFileNameProvided when the filename provided is empty
var ErrNoFileNameProvided = errors.New("no filename provided")

// GetFileType returns the correct file type based on the input one.
func GetFileType(fileName string) (FileType, error) {
	switch {
	case fileName == "":
		return FileTypeUnsupported, ErrNoFileNameProvided
	case strings.HasSuffix(fileName, ".tar"):
		return FileTypeTar, nil
	case strings.HasSuffix(fileName, ".tar.gz"):
		return FileTypeTarGz, nil
	case strings.HasSuffix(fileName, ".zip"):
		return FileTypeZip, nil
	}

	return FileTypeUnarchived, nil
}

// ErrUnknownArchiveType is returned when the archive type is not supported by
// the system
var ErrUnknownArchiveType = errors.New("archive type provided is not supported")

// GetArchiveType returns the correct file type based on the input one.
func GetArchiveType(archiveType string) (FileType, error) {
	switch {
	case archiveType == "":
		return FileTypeUnarchived, nil
	case archiveType == "tar":
		return FileTypeTar, nil
	case archiveType == "tar.gz":
		return FileTypeTarGz, nil
	case archiveType == "zip":
		return FileTypeZip, nil
	default:
		return FileTypeUnsupported, errors.Errorf("%s: %w", archiveType, ErrUnknownArchiveType)
	}
}
