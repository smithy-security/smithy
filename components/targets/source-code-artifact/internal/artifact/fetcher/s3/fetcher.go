package s3

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconf "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"
	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact"
	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/artifact/fetcher"
)

type (
	// awsLoggerProxy is a hack to get our component logger to work with AWS
	// logging infra
	awsLoggerProxy func() logger.Logger

	s3Fetcher struct {
		s3Client *s3.Client
		conf     fetcher.Config
	}

	// ArtifactDetailsConstrFn configures s3 bucket entries.
	ArtifactDetailsConstrFn func(artifactURL string) (string, string, string, error)
)

// Logf implements the aws Logger interface.
func (a awsLoggerProxy) Logf(classification logging.Classification, format string, v ...any) {
	if classification == logging.Debug {
		a().Debug(format, v...)
	} else {
		a().Warn(format, v...)
	}
}

// NewFetcher returns a new s3/gcs compatible s3 client.
func NewFetcher(
	ctx context.Context,
	sourceType artifact.SourceType,
	cfg fetcher.Config,
	detailsConstr ArtifactDetailsConstrFn,
) (s3Fetcher, error) {
	var err error
	cfg.ArtifactBaseURL, cfg.BucketName, cfg.KeyName, err = detailsConstr(cfg.ArtifactURL)
	if err != nil {
		return s3Fetcher{}, errors.Errorf("could not determine artifact URL: %s", cfg.ArtifactURL)
	}

	s3Client, err := newS3Client(ctx, sourceType, cfg)
	if err != nil {
		return s3Fetcher{}, errors.Errorf("could not configure s3 s3Fetcher: %w", err)
	}

	return s3Fetcher{
		s3Client: s3Client,
		conf:     cfg,
	}, nil
}

// GCSDetailsConstructor peculiar constructor for GCS that requires a specific base endpoint.
func GCSDetailsConstructor(artifactURLStr string) (string, string, string, error) {
	bucketName, keyName, err := getDetails(strings.TrimPrefix(artifactURLStr, "gs://"))
	return "https://storage.googleapis.com", bucketName, keyName, err
}

// DetailsConstructor doesn't specify an endpoint as the SDK is able to auto-resolve it.
func DetailsConstructor(artifactURLStr string) (string, string, string, error) {
	bucketName, keyName, err := getDetails(strings.TrimPrefix(artifactURLStr, "s3://"))
	return "", bucketName, keyName, err
}

func getDetails(artifactURL string) (string, string, error) {
	ap := strings.Split(artifactURL, "/")
	if len(ap) < 2 {
		return "", "", errors.New("artifact URL must contain a bucket and key")
	}

	var (
		bucketName = strings.Join(ap[:len(ap)-1], "/")
		keyName    = ap[len(ap)-1]
	)

	return bucketName, keyName, nil
}

// FetchArtifact fetches the artifact from s3.
func (f s3Fetcher) FetchArtifact(ctx context.Context) (io.ReadCloser, error) {
	var (
		bucketName = f.conf.BucketName
		keyName    = f.conf.KeyName
		l          = logger.
				LoggerFromContext(ctx).
				With(
				slog.String("bucket", bucketName),
				slog.String("key", keyName),
			)
	)

	l.Debug("fetching artifact...")
	res, err := f.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(keyName),
	})
	if err != nil {
		var noKey *types.NoSuchKey
		if errors.As(err, &noKey) {
			return nil, errors.Errorf("%s, %s: no such key inside the bucket: %w", bucketName, keyName, err)
		}

		return nil, errors.Errorf("%s, %s: there was an error downloading the file: %w", bucketName, keyName, err)
	}
	l.Debug("fetched artifact correctly!")

	return res.Body, nil
}

func newS3Client(ctx context.Context, sourceType artifact.SourceType, cfg fetcher.Config) (*s3.Client, error) {
	awsOpts, s3Opts := newS3Options(ctx, sourceType, cfg)

	c, err := awsconf.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, errors.Errorf("could not create s3 client: %w", err)
	}

	return s3.NewFromConfig(c, s3Opts...), nil
}

func newS3Options(
	ctx context.Context,
	sourceType artifact.SourceType,
	cfg fetcher.Config,
) ([]func(*awsconf.LoadOptions) error, []func(*s3.Options)) {
	var (
		awsOpts = []func(*awsconf.LoadOptions) error{
			awsconf.WithLogger(
				awsLoggerProxy(
					func() logger.Logger {
						return logger.LoggerFromContext(ctx)
					},
				),
			),
		}
		s3Opts []func(*s3.Options)
		region = "auto"
	)

	if cfg.Region != "" {
		region = cfg.Region
	}
	awsOpts = append(awsOpts, awsconf.WithRegion(region))

	if sourceType == artifact.SourceTypeGCS {
		s3Opts = append(s3Opts, signForGCP)
		awsOpts = append(awsOpts, awsconf.WithBaseEndpoint(cfg.ArtifactBaseURL))
	}

	if cfg.AuthID != "" && cfg.AuthSecret != "" {
		logger.LoggerFromContext(ctx).Debug(
			"authenticating with auth id and secret",
			slog.String("auth_id", fetcher.Redact(cfg.AuthID)),
			slog.String("auth_secret", fetcher.Redact(cfg.AuthSecret)),
		)
		awsOpts = append(awsOpts, awsconf.WithCredentialsProvider(
			aws.CredentialsProviderFunc(
				func(_ context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     cfg.AuthID,
						SecretAccessKey: cfg.AuthSecret,
					}, nil
				},
			),
		))
	} else {
		awsOpts = append(awsOpts, awsconf.WithCredentialsProvider(aws.AnonymousCredentials{}))
	}

	if cfg.BaseHTTPClient != nil {
		awsOpts = append(awsOpts, awsconf.WithHTTPClient(cfg.BaseHTTPClient))
	}

	return awsOpts, s3Opts
}
