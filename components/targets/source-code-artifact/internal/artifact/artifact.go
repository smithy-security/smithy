package artifact

import (
	"strings"

	"github.com/go-errors/errors"
)

const (
	SourceTypeS3          SourceType = "s3"
	SourceTypeGCS         SourceType = "gcs"
	SourceTypeRemote      SourceType = "remote"
	SourceTypeUnsupported SourceType = "unsupported"

	FileTypeZip         FileType = "zip"
	FileTypeTar         FileType = "tar"
	FileTypeTarGz       FileType = "tar.gz"
	FileTypeUnarchived  FileType = "unarchived"
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

// GetFileType returns the correct file type based on the input one.
func GetFileType(fileName string) (FileType, error) {
	switch {
	case fileName == "":
		return FileTypeUnsupported, nil
	case strings.HasSuffix(fileName, ".tar"):
		return FileTypeTar, nil
	case strings.HasSuffix(fileName, ".tar.gz"):
		return FileTypeTarGz, nil
	case strings.HasSuffix(fileName, ".zip"):
		return FileTypeZip, nil
	}

	return FileTypeUnarchived, nil
}
