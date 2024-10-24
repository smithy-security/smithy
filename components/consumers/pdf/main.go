// Package main of the pdf consumer implements a simple consumer for
// applying a go-template to a smithy scan, converting the result to pdf and then
// uploading the result to the S3 bucket passed as an argument
// the consumer expects the environment variables
// AWS_ACCESS_KEY_ID
// AWS_SECRET_ACCESS_KEY
// to be set along with the "bucket" and "region" arguments to be passed
package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/smithy-security/smithy/components/consumers"
	playwright "github.com/smithy-security/smithy/pkg/playwright"
	s3client "github.com/smithy-security/smithy/pkg/s3"
)

var (
	bucket         string
	region         string
	reportTemplate string
)

func main() {

	flag.StringVar(&bucket, "bucket", "", "s3 bucket name")
	flag.StringVar(&region, "region", "", "s3 bucket region")
	flag.StringVar(&reportTemplate, "template", "", "report html template location")

	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	if bucket == "" {
		log.Fatal("bucket is empty, you need to provide a bucket value")
	}

	if region == "" {
		log.Fatal("region is empty, you need to provide a region value")
	}

	var responses any
	var scanID string
	if consumers.Raw {
		r, err := consumers.LoadToolResponse()
		if err != nil {
			log.Fatal("could not load raw results, file malformed: ", err)
		}
		responses = r
		scanID = r[0].ScanInfo.ScanUuid
	} else {
		r, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			log.Fatal("could not load enriched results, file malformed: ", err)
		}
		responses = r
		scanID = r[0].OriginalResults.ScanInfo.ScanUuid
	}

	cleanupRun := func(msg string, cleanup func() error) {
		if err := cleanup(); err != nil {
			slog.Error(msg, "error", err)
		}
	}

	pw, err := playwright.NewClient()
	if err != nil {
		log.Fatalf("could not launch playwright: %s", err)
	}

	defer cleanupRun("could not stop Playwright: %w", pw.Stop)

	client, err := s3client.NewClient(region)
	if err != nil {
		log.Fatal(err)
	}

	if err := run(responses, scanID, pw, client); err != nil {
		log.Fatal(err)
	}
}

func run(responses any, s3FilenamePostfix string, pw playwright.Wrapper, s3Wrapper s3client.Wrapper) error {
	slog.Info("reading pdf")
	resultFilename, pdfBytes, err := buildPdf(responses, pw)
	if err != nil {
		return err
	}

	slog.Info("uploading pdf to s3", slog.String("filename", resultFilename), slog.String("bucket", bucket), slog.String("region", region))
	return s3Wrapper.UpsertFile(resultFilename, bucket, s3FilenamePostfix, pdfBytes)
}

func buildPdf(data any, pw playwright.Wrapper) (string, []byte, error) {
	tmpl, err := template.ParseFiles("default.html")
	if err != nil {
		return "", nil, err
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

	reportPage := fmt.Sprintf("file:///%s", reportHTMLPath)
	pdfBytes, err := pw.GetPDFOfPage(reportPage, reportHTMLPath)
	if err != nil {
		return "", nil, fmt.Errorf("could not generate pdf from page %s, err: %w", reportPage, err)

	}
	return reportHTMLPath, pdfBytes, err
}
