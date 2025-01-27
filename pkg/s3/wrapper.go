package wrapper

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/go-errors/errors"
)

// Wrapper is the wrapper interface that allows the playwright client to be pluggable
type Wrapper interface {
	// UpsertFile inserts or replaces a file in s3 if it doesn't exist
	UpsertFile(string, string, string, []byte) error
}

// Client is the wrapper around google's go-github client
type Client struct {
	session *session.Session
}

// NewClient returns a client
func NewClient(region string) (Client, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		return Client{}, errors.Errorf("unable to start session with AWS API: %w", err)
	}
	// create new playwright client
	return Client{
		session: sess,
	}, nil
}

// FormatFilename prepares a filename for S3:
// - removes the filepath
// - adds a suffix if it exists
func FormatFilename(filename, suffix string) string {
	ext := filepath.Ext(filename)        // Get the file extension (e.g., .pdf)
	name := filepath.Base(filename)      // remove the filepath from the filename
	name = strings.TrimSuffix(name, ext) // Remove the extension from the filename
	if suffix != "" {
		return fmt.Sprintf("%s-%s%s", name, suffix, ext) // Add the suffix if it exists
	}
	return fmt.Sprintf("%s%s", name, ext) // Return the original filename if no suffix
}

// UpsertFile uploads or replaces a file on s3
func (c Client) UpsertFile(filename, bucket, s3FilenameSuffix string, pdfBytes []byte) error {
	//#nosec:G304
	data, err := os.ReadFile(filename) //#nosec:G304
	if err != nil {
		return errors.Errorf("could not open file: %w", err)
	}
	uploadFilename := FormatFilename(filename, s3FilenameSuffix)
	uploader := s3manager.NewUploader(c.session)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(uploadFilename),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return errors.Errorf("unable to upload %s to %s: %w", filename, bucket, err)
	}
	slog.Info("uploaded", "filename", filename, "to", "bucket", bucket, "successfully")
	return nil
}
