package fs

import (
	"fmt"
	"path/filepath"

	"github.com/go-errors/errors"
	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/putil"
)

// ReadWriter is responsible from reading/writing from/to the filesystem.
type ReadWriter struct {
	writePath string
	readPath  string
}

// NewReadWriter returns a new read/writer.
func NewReadWriter(readPath, writePath string) (*ReadWriter, error) {
	switch {
	case readPath == "":
		return nil, errors.New("invalid empty read path provided")
	case writePath == "":
		return nil, errors.New("invalid empty write path provided")
	}

	return &ReadWriter{
		writePath: writePath,
		readPath:  readPath,
	}, nil
}

// ReadTaggedResponse scans the supplied tag responses path for reports and parses them into *v1.LaunchToolResponse.
func (rw *ReadWriter) ReadTaggedResponse() ([]*v1.LaunchToolResponse, error) {
	res, err := putil.LoadTaggedToolResponse(rw.readPath)
	if err != nil {
		return nil, errors.Errorf("failed to read tagged tool response: %w", err)
	}
	return res, nil
}

// WriteEnrichedResults writes the tagged report.
func (rw *ReadWriter) WriteEnrichedResults(
	original *v1.LaunchToolResponse,
	enrichedIssues []*v1.EnrichedIssue,
) error {
	if len(enrichedIssues) == 0 {
		return nil
	}

	writePath := filepath.Join(
		rw.writePath,
		fmt.Sprintf(
			"%s.reachability.enriched.pb",
			original.GetToolName(),
		),
	)

	if err := putil.WriteEnrichedResults(original, enrichedIssues, writePath); err != nil {
		return errors.Errorf("error writing enriched results on path %s: %w", writePath, err)
	}

	return nil
}

// WriteRawResults writes the raw report that was given in input.
func (rw *ReadWriter) WriteRawResults(original *v1.LaunchToolResponse) error {
	var (
		issues    = original.GetIssues()
		toolName  = original.GetToolName()
		writePath = filepath.Join(
			rw.writePath,
			fmt.Sprintf(
				"%s.raw.pb",
				toolName,
			),
		)
		scanInfo = original.GetScanInfo()
	)

	if len(issues) == 0 {
		return nil
	}

	if err := putil.WriteResults(
		toolName,
		issues,
		writePath,
		scanInfo.GetScanUuid(),
		scanInfo.GetScanStartTime().AsTime(),
		scanInfo.GetScanTags(),
	); err != nil {
		return errors.Errorf("error writing raw results on path %s: %w", writePath, err)
	}

	return nil
}
