package component_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/mocks"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
)

func runReporterHelper(
	t *testing.T,
	ctx context.Context,
	instanceID uuid.UUID,
	reporter component.Reporter,
	store component.Storer,
) error {
	t.Helper()

	return component.RunReporter(
		ctx,
		reporter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-reporter"),
		component.RunnerWithInstanceID(instanceID),
		component.RunnerWithStorer(store),
	)
}

func TestRunReporter(t *testing.T) {
	var (
		ctrl, ctx    = gomock.WithContext(context.Background(), t)
		instanceID   = uuid.New()
		mockCtx      = gomock.AssignableToTypeOf(ctx)
		mockStore    = mocks.NewMockStorer(ctrl)
		mockReporter = mocks.NewMockReporter(ctrl)
		vulns        = make([]*vf.VulnerabilityFinding, 0)
	)

	t.Run("it should run a reporter correctly", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				DoAndReturn(func(ctx context.Context, instanceID uuid.UUID) ([]*vf.VulnerabilityFinding, error) {
					cancel()
					return vulns, nil
				}),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*vf.VulnerabilityFinding) error {
					<-ctx.Done()
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		var errRead = errors.New("reader-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(nil, errRead),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore), errRead)
	})

	t.Run("it should return early when reporting errors", func(t *testing.T) {
		var errReporting = errors.New("reporting-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				Return(errReporting),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore), errReporting)
	})

	t.Run("it should return early when a panic is detected on reporting", func(t *testing.T) {
		var errReporting = errors.New("reporting-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*vf.VulnerabilityFinding) error {
					panic(errReporting)
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore), errReporting)
	})
}
