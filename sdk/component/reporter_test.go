package component_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/mocks"
	"github.com/smithy-security/smithy/sdk/component/store"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	sdklogger "github.com/smithy-security/smithy/sdk/logger"
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
		component.RunnerWithLogger(sdklogger.NewNoopLogger()),
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
		vulns        = make([]*vf.VulnerabilityFinding, 2)
	)

	t.Run("it should run a reporter correctly", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID, nil).
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
				Read(mockCtx, instanceID, nil).
				DoAndReturn(func(ctx context.Context, instanceID uuid.UUID, _ *store.QueryOpts) ([]*vf.VulnerabilityFinding, error) {
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
				Read(mockCtx, instanceID, nil).
				Return(nil, errRead),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore), errRead)
	})

	t.Run("it should return early when the store errors with no findings were found error", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID, nil).
				Return(nil, store.ErrNoFindingsFound),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore))
	})

	t.Run("it should return early when no findings were found", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID, nil).
				Return(make([]*vf.VulnerabilityFinding, 0), nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore))
	})
	t.Run("it should NOT return early when no findings were found if the environment variable 'envVarKeyRunReportersWithoutFindings' is set", func(t *testing.T) {
		os.Setenv("SMITHY_RUN_REPORTER_WITHOUT_FINDINGS", "true")
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID, nil).
				Return(make([]*vf.VulnerabilityFinding, 0), nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, []*vf.VulnerabilityFinding{}).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)
		require.NoError(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore))
		os.Unsetenv("SMITHY_RUN_REPORTER_WITHOUT_FINDINGS")
	})
	t.Run("it should return early when reporting errors", func(t *testing.T) {
		var errReporting = errors.New("reporting-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID, nil).
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
				Read(mockCtx, instanceID, nil).
				Return(vulns, nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*vf.VulnerabilityFinding) error {
					panic(errReporting)
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runReporterHelper(t, ctx, instanceID, mockReporter, mockStore), errReporting)
	})
}
