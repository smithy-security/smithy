// Package main of the pdf consumer implements a simple consumer for
// applying a go-template to a smithy scan, converting the result to pdf and then
// uploading the result to the S3 bucket passed as an argument
// the consumer expects the environment variables
// AWS_ACCESS_KEY_ID
// AWS_SECRET_ACCESS_KEY
// to be set along with the "bucket" and "region" arguments to be passed
package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	playwright "github.com/smithy-security/smithy/pkg/playwright/mock"
	s3mock "github.com/smithy-security/smithy/pkg/s3/mock"
	"github.com/smithy-security/smithy/pkg/testdata"
)

func Test_run(t *testing.T) {
	mockClient, err := playwright.NewMockClient()
	require.NoError(t, err)

	pdfCalled := false
	expected := []byte("this is a pdf")
	mockClient.GetPDFOfPageCallBack = func(s1, s2 string) ([]byte, error) {
		pdfCalled = true
		return expected, nil
	}

	mockS3Client, err := s3mock.NewMockClient("")
	require.NoError(t, err)
	s3Called := false
	mockS3Client.UpsertCallback = func(s1, s2 string, b []byte) error {
		s3Called = true
		return nil
	}

	err = run([]v1.EnrichedLaunchToolResponse{testdata.EnrichedLaunchToolResponse}, "", mockClient, mockS3Client)
	require.NoError(t, err)
	require.True(t, pdfCalled)
	require.True(t, s3Called)

}

func Test_buildPdf(t *testing.T) {
	mockClient, err := playwright.NewMockClient()
	require.NoError(t, err)

	called := false
	expected := []byte("this is a pdf")
	mockClient.GetPDFOfPageCallBack = func(s1, s2 string) ([]byte, error) {
		called = true
		return expected, nil
	}
	_, result, err := buildPdf([]v1.EnrichedLaunchToolResponse{testdata.EnrichedLaunchToolResponse}, mockClient)
	require.NoError(t, err)
	require.Equal(t, called, true)
	require.Equal(t, result, expected)
}
