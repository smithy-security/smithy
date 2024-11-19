package wrapper

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

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

// NewClient returns a client
func NewClient(region string) (Client, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		return Client{}, fmt.Errorf("unable to start session with AWS API: %w", err)
	}
	// create new playwright client
	return Client{
		session: sess,
	}, nil
}

func (c Client) UpsertFile(filename, bucket, filenamePrefix string, pdfBytes []byte) error {
	//#nosec:G304
	data, err := os.ReadFile(filename) //#nosec:G304
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}

	uploader := s3manager.NewUploader(c.session)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(filenamePrefix + filename),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("unable to upload %s to %s: %w", filename, bucket, err)
	}
	slog.Info("uploaded", "filename", filename, "to", "bucket", bucket, "successfully")
	return nil
}
