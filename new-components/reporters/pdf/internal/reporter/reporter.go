package reporter

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	playwright "github.com/smithy-security/smithy/pkg/playwright"
	s3client "github.com/smithy-security/smithy/pkg/s3"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
)

// NewReporter returns a new PDF reporter.
func NewReporter(conf *Conf) *PdfReporter {
	return &PdfReporter{
		conf: conf,
	}
}

type PdfReporter struct {
	conf *Conf
}

type (
	Conf struct {
		InstanceId   string
		Bucket       string
		Region       string
		SkipS3Upload bool
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	instanceId, err := env.GetOrDefault(
		"SMITHY_INSTANCE_ID",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get SMITHY_INSTANCE_ID: %w", err)
	}

	skipS3Upload, err := env.GetOrDefault(
		"SKIP_S3_UPLOAD",
		true,
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SKIP_S3_UPLOAD: %w", err)
	}

	bucket, err := env.GetOrDefault(
		"BUCKET_NAME",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for BUCKET_NAME: %w", err)
	}

	region, err := env.GetOrDefault(
		"BUCKET_REGION",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for BUCKET_REGION: %w", err)
	}

	return &Conf{
		InstanceId:   instanceId,
		Bucket:       bucket,
		Region:       region,
		SkipS3Upload: skipS3Upload,
	}, nil
}

func (p PdfReporter) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := component.LoggerFromContext(ctx).With(slog.Bool("s3_upload_disabled", p.conf.SkipS3Upload))

	// get the Playwright client
	pw, err := getPlayWright()
	if err != nil {
		return fmt.Errorf("could not initialise PlayWright: %w", err)
	}
	logger.Info("started Playwright")

	// get the PDF
	resultFilename, pdfBytes, err := p.getPdf(findings, pw)
	if err != nil {
		return fmt.Errorf("could not build pdf: %w", err)
	}
	logger.Info("built the PDF")

	// do we need to upload to AWS S3 ?
	if p.conf.SkipS3Upload {
		logger.Info("skipping S3 upload because it is disabled")
		return nil
	}

	// start the s3 client
	s3, err := getS3Client(p.conf.Region)
	if err != nil {
		return fmt.Errorf("could not initialise s3 client: %w", err)
	}
	logger.Info("started S3 client")

	// upload to s3
	logger.Info("uploading to S3")
	err = p.uploadToS3(resultFilename, pdfBytes, s3)
	if err != nil {
		return fmt.Errorf("could not upload to S3: %w", err)
	}
	logger.Info("SUCCESS: uploaded to S3")
	return nil
}

// getPlayWright initializes tha playwright client
func getPlayWright() (*playwright.Client, error) {
	pw, err := playwright.NewClient()
	if err != nil {
		slog.Error("could not launch playwright: %s", slog.String("err", err.Error()))
		return nil, err
	}
	return &pw, nil
}

// getPdf initializes Playwright and starts the PDF generation
func (p PdfReporter) getPdf(findings []*vf.VulnerabilityFinding, pw *playwright.Client) (string, []byte, error) {
	defer func() {
		if err := pw.Stop(); err != nil {
			slog.Error("could not stop Playwright", slog.String("err", err.Error()))
		}
	}()

	slog.Info("reading PDF")
	resultFilename, pdfBytes, err := p.buildPdf(findings, pw)
	if err != nil {
		return "", nil, fmt.Errorf("could not build pdf: %w", err)
	}
	slog.Info("result filename", slog.String("filename", resultFilename))

	return resultFilename, pdfBytes, nil
}

//go:embed template.html
var templateFile string

// buildPdf builds a PDF
func (p PdfReporter) buildPdf(data any, pw playwright.Wrapper) (string, []byte, error) {
	// process the default template into a html result
	tmpl, err := template.New("template.html").Funcs(template.FuncMap{
		"formatTime": FormatTime,
	}).Parse(templateFile)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse files: %w", err)
	}

	currentPath, err := os.Getwd()
	if err != nil {
		return "", nil, fmt.Errorf("could not get current working directory: %w", err)
	}

	reportHTMLPath := filepath.Join(currentPath, "report.html")
	//#nosec: G304
	f, err := os.OpenFile(reportHTMLPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //#nosec: G304
	if err != nil {
		return "", nil, fmt.Errorf("could not open report.html: %w", err)
	}
	if err = tmpl.Execute(f, data); err != nil {
		return "", nil, fmt.Errorf("could not apply data to template: %w", err)
	}
	// close the file after writing it
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			slog.Error("could not close file", slog.String("err", err.Error()))
		}
	}(f)

	reportPDFPath := filepath.Join(currentPath, "report.pdf")
	reportPage := fmt.Sprintf("file:///%s", reportHTMLPath)
	pdfBytes, err := pw.GetPDFOfPage(reportPage, reportPDFPath)
	if err != nil {
		return "", nil, fmt.Errorf("could not generate pdf from page %s, err: %w", reportPage, err)
	}

	// delete the intermediate HTML file
	if err := os.Remove(reportHTMLPath); err != nil {
		slog.Error("could not delete report.html", slog.String("err", err.Error()))
	}
	return reportPDFPath, pdfBytes, err
}

// FormatTime is a template function for the PDF, that converts a timestamp to a human-readable format
func FormatTime(timestamp *int64) string {
	if timestamp == nil {
		return ""
	}

	// Convert the int64 value to a time.Time
	parsedTime := time.Unix(*timestamp, 0)

	// Format the time using a predefined layout
	return parsedTime.Format(time.DateTime)
}

// getS3Client initializes the s3 client, so we can upload the PDF there
func getS3Client(region string) (*s3client.Client, error) {
	if region == "" {
		err := errors.New("region is empty, you need to provide a region name")
		return nil, err
	}

	client, err := s3client.NewClient(region)

	if err != nil {
		slog.Error("could not launch s3 client: %s", slog.String("err", err.Error()))
		return nil, err
	}
	return &client, nil
}

// uploadToS3 uploads the PDF to AWS via the s3 client
func (p PdfReporter) uploadToS3(resultFilename string, pdfBytes []byte, s3client *s3client.Client) error {
	if p.conf.Bucket == "" {
		slog.Error("bucket is empty, you need to provide a bucket name")
	}

	if p.conf.InstanceId == "" {
		slog.Error("InstanceId is empty, you need to provide an instance id")
	}

	filenameSuffix := p.conf.InstanceId
	slog.Info("uploading pdf to s3", slog.String("filename", resultFilename), slog.String("bucket", p.conf.Bucket), slog.String("region", p.conf.Region))
	return s3client.UpsertFile(resultFilename, p.conf.Bucket, filenameSuffix, pdfBytes)
}
