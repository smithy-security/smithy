package wrapper

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
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
type Option func(aws.Config) aws.Config

// WithRegion allows providing a custom AWS region.
func WithRegion(region string) Option {
	return func(c aws.Config) aws.Config {
		region = strings.TrimSpace(region)
		if region != "" {
			c.Region = aws.String(region)
		}
		return c
	}
}

// WithEndpoint allows providing a custom AWS endpoint.
// useful for localstack or other S3-compatible services.
func WithEndpoint(endpoint string) Option {
	return func(c aws.Config) aws.Config {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint != "" {
			c.Endpoint = aws.String(endpoint)
		}
		return c
	}
}

// NewClient returns an AWS Client.
func NewClient(opts ...Option) (Client, error) {
	config := aws.Config{}
	for _, opt := range opts {
		config = opt(config)
	}
	if config.Endpoint != nil {
		log.Printf("Using custom S3 endpoint: %s and setting PathStyle over SubdomainStyle", *config.Endpoint)
		// a lot of local/testing S3 implementations that need custom endoints do not support the default subdomain style
		config.S3ForcePathStyle = aws.Bool(true)
	}
	sess, err := session.NewSession(&config)
	if err != nil {
		return Client{}, fmt.Errorf("unable to start session with AWS API: %w", err)
	}
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
		return fmt.Errorf("could not open file: %w", err)
	}
	uploadFilename := FormatFilename(filename, s3FilenameSuffix)
	uploader := s3manager.NewUploader(c.session)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(uploadFilename),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("unable to upload %s to %s: %w", filename, bucket, err)
	}
	slog.Info("uploaded", "filename", filename, "to", "bucket", bucket, "successfully")
	return nil
}
