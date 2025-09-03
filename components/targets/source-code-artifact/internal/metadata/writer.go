package metadata

import (
	"context"
	"os"

	"github.com/go-errors/errors"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

type (
	// Config contains writer's conf.
	Config struct {
		ArtifactURL   string
		ArtifactID    string
		RepositoryURL string
		Reference     string
		MetadataPath  string
		FileType      artifact.FileType
	}

	// JSONWriter writes the metadata provided to it as a JSON document to the
	// filesystem
	JSONWriter struct {
		cfg Config
	}
)

// NewWriter returns a new metadata writer.
func NewWriter(cfg Config) JSONWriter {
	return JSONWriter{cfg: cfg}
}

// WriteMetadata writes target metadata.
func (w JSONWriter) WriteMetadata(ctx context.Context) error {
	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      w.cfg.ArtifactID,
		},
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: w.cfg.RepositoryURL,
			Reference:     w.cfg.Reference,
		},
	}

	marshaledDataSource, err := protojson.Marshal(dataSource)
	if err != nil {
		return errors.Errorf("could not marshal data source into JSON: %w", err)
	}

	fd, err := os.OpenFile(w.cfg.MetadataPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return errors.Errorf("could not open file to report clone metadata: %w", err)
	}

	defer reader.CloseReader(ctx, fd)

	if _, err := fd.Write(marshaledDataSource); err != nil {
		return errors.Errorf("could not write data to file: %w", err)
	}

	return nil
}
