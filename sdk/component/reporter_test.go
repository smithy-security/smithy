package component_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/mocks"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runReporterHelper(t *testing.T, ctx context.Context, reporter component.Reporter) error {
	t.Helper()

	return component.RunReporter(
		ctx,
		reporter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-reporter"),
	)
}

func TestRunReporter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl  = gomock.NewController(t)
		vulns = make([]*ocsf.VulnerabilityFinding, 0)
	)

	t.Run("it should run a reporter correctly", func(t *testing.T) {
		mockReporter := mocks.NewMockReporter(ctrl)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockReporter.
			EXPECT().
			Report(gomock.Any(), vulns).
			Return(nil)
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runReporterHelper(t, ctx, mockReporter))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockReporter := mocks.NewMockReporter(ctrl)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			DoAndReturn(func(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
				cancel()
				return vulns, nil
			})
		mockReporter.
			EXPECT().
			Report(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				<-ctx.Done()
				return nil
			})
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runReporterHelper(t, ctx, mockReporter))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		var (
			errRead      = errors.New("reader-is-sad")
			mockReporter = mocks.NewMockReporter(ctrl)
		)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			Return(nil, errRead)
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runReporterHelper(t, ctx, mockReporter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when reporting errors", func(t *testing.T) {
		var (
			errReporting = errors.New("reporting-is-sad")
			mockReporter = mocks.NewMockReporter(ctrl)
		)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockReporter.
			EXPECT().
			Report(gomock.Any(), vulns).
			Return(errReporting)
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runReporterHelper(t, ctx, mockReporter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errReporting)
	})

	t.Run("it should keep shutting down the application when a panic is detected during close", func(t *testing.T) {
		mockReporter := mocks.NewMockReporter(ctrl)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockReporter.
			EXPECT().
			Report(gomock.Any(), vulns).
			Return(nil)
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errors.New("close-is-sad"))
				return nil
			})

		err := runReporterHelper(t, ctx, mockReporter)
		require.NoError(t, err)
	})

	t.Run("it should return early when a panic is detected on reporting", func(t *testing.T) {
		var (
			errReporting = errors.New("reporting-is-sad")
			mockReporter = mocks.NewMockReporter(ctrl)
		)

		mockReporter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockReporter.
			EXPECT().
			Report(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				panic(errReporting)
				return nil
			})
		mockReporter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runReporterHelper(t, ctx, mockReporter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errReporting)
	})
}
