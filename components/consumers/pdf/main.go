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
	"time"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/smithy/components/consumers"
	playwright "github.com/smithy-security/smithy/pkg/playwright"
	s3client "github.com/smithy-security/smithy/pkg/s3"
)

var (
	bucket         string
	region         string
	reportTemplate string
	skipS3Upload   bool
)

func main() {

	flag.StringVar(&bucket, "bucket", "", "s3 bucket name")
	flag.StringVar(&region, "region", "", "s3 bucket region")
	flag.StringVar(&reportTemplate, "template", "default.html", "report html template location")
	flag.BoolVar(&skipS3Upload, "skips3", false, "skip s3 upload")

	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	if bucket == "" && !skipS3Upload {
		log.Fatal("bucket is empty, you need to provide a bucket value")
	}

	if region == "" && !skipS3Upload {
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

	pw, err := playwright.NewClient()
	if err != nil {
		log.Fatalf("could not launch playwright: %s", err)
	}

	defer func() {
		if err := pw.Stop(); err != nil {
			slog.Error("could not stop Playwright", slog.String("err", err.Error()))
		}
	}()

	client, err := s3client.NewClient(region)
	if err != nil {
		log.Fatal(err)
	}

	if err := run(responses, scanID, pw, client); err != nil {
		log.Fatal(err)
	}
}

func run(responses any, s3FilenameSuffix string, pw playwright.Wrapper, s3Wrapper s3client.Wrapper) error {
	slog.Info("reading pdf")
	resultFilename, pdfBytes, err := buildPdf(responses, pw)
	if err != nil {
		return errors.Errorf("could not build pdf: %w", err)
	}
	slog.Info("result filename", slog.String("filename", resultFilename))

	if !skipS3Upload {
		slog.Info("uploading pdf to s3", slog.String("filename", resultFilename), slog.String("bucket", bucket), slog.String("region", region))
		return s3Wrapper.UpsertFile(resultFilename, bucket, s3FilenameSuffix, pdfBytes)
	}
	return nil
}

func buildPdf(data any, pw playwright.Wrapper) (string, []byte, error) {
	templateFile := reportTemplate
	if templateFile == "" {
		templateFile = "default.html"
	}

	// process the default template into a html result
	tmpl, err := template.New("default.html").Funcs(template.FuncMap{
		"formatTime": formatTime,
	}).ParseFiles(templateFile)
	if err != nil {
		return "", nil, errors.Errorf("could not parse files: %w", err)
	}

	currentPath, err := os.Getwd()
	if err != nil {
		return "", nil, errors.Errorf("could not get current working directory: %w", err)
	}

	reportHTMLPath := filepath.Join(currentPath, "report.html")
	//#nosec: G304
	f, err := os.OpenFile(reportHTMLPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //#nosec: G304
	if err != nil {
		return "", nil, errors.Errorf("could not open report.html: %w", err)
	}
	if err = tmpl.Execute(f, data); err != nil {
		return "", nil, errors.Errorf("could not apply data to template: %w", err)
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
		return "", nil, errors.Errorf("could not generate pdf from page %s, err: %w", reportPage, err)

	}

	// delete the intermediate HTML file
	if err := os.Remove(reportHTMLPath); err != nil {
		slog.Error("could not delete report.html", slog.String("err", err.Error()))
	}
	return reportPDFPath, pdfBytes, err
}

// formatTime is a template function that converts a timestamp to a human-readable format
func formatTime(timestamp *timestamppb.Timestamp) string {
	parsedTime := timestamp.AsTime()
	return parsedTime.Format(time.DateTime)
}
