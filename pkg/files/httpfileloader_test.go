package files

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/pkg/http/mock"
	"github.com/smithy-security/smithy/pkg/utils"
)

func TestHTTPFileLoaderInit(t *testing.T) {
	_, err := newHTTPFileLoader("-", "kustomization.yaml")
	require.ErrorIs(t, err, ErrInvalidURL)

	fl, err := newHTTPFileLoader("https://github.com/smithy-security/smithy/pkg", "kustomization.yaml")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/smithy-security/smithy/pkg/kustomization.yaml", fl.Path())

	fl, err = newHTTPFileLoader("https://github.com/smithy-security/smithy/pkg/kustomization.yaml", "kustomization.yaml")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/smithy-security/smithy/pkg/kustomization.yaml", fl.Path())
}

func TestHTTPFileLoaderLoad(t *testing.T) {
	testCases := []struct {
		name            string
		url             string
		targetFile      string
		mockRequestDoer utils.MockableRequestDoer
		expectedURL     string
		expectedErr     error
	}{
		{
			name:       "success",
			url:        "https://github.com/smithy-security/smithy/pkg",
			targetFile: "kustomization.yaml",
			mockRequestDoer: &mock.HTTPReqDoer{
				Hook: func(req *http.Request) (*http.Response, error) {
					require.Equal(t, "https://github.com/smithy-security/smithy/pkg/kustomization.yaml", req.URL.String())

					recorder := httptest.NewRecorder()
					recorder.Code = http.StatusOK
					_, err := recorder.WriteString(`---
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
nameSuffix: -golang-project
resources:
	- ../../../components/base/pipeline.yaml
	- ../../../components/base/task.yaml
components:
	- ../../../components/sources/git`)
					require.NoError(t, err)
					return recorder.Result(), nil
				},
			},
		},
		{
			name:       "404",
			url:        "https://github.com/smithy-security/smithy/pkg",
			targetFile: "kustomization.yaml",
			mockRequestDoer: &mock.HTTPReqDoer{
				Hook: func(req *http.Request) (*http.Response, error) {
					require.Equal(t, "https://github.com/smithy-security/smithy/pkg/kustomization.yaml", req.URL.String())

					recorder := httptest.NewRecorder()
					recorder.Code = http.StatusNotFound
					return recorder.Result(), nil
				},
			},
			expectedURL: "https://github.com/smithy-security/smithy/pkg/kustomization.yaml",
			expectedErr: ErrUnsuccessfulRequest,
		},
	}

	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fl, err := newHTTPFileLoader("https://github.com/smithy-security/smithy/pkg", "kustomization.yaml")
			require.NoError(t, err)

			runCtx, cancel := context.WithCancel(testCtx)
			defer cancel()

			fl.client = testCase.mockRequestDoer
			_, err = fl.Load(runCtx)
			require.ErrorIs(t, err, testCase.expectedErr)
		})
	}
}

func TestCancelledContext(t *testing.T) {
	fl, err := newHTTPFileLoader("https://github.com/smithy-security/smithy/pkg", "kustomization.yaml")
	require.NoError(t, err)

	runCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fl.Load(runCtx)
	require.ErrorIs(t, err, context.Canceled)
}
