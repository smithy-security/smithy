package component_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/internal/mocks"
	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runReporterHelper(
	t *testing.T,
	ctx context.Context,
	workflowID uuid.UUID,
	reporter component.Reporter,
	store component.Storer,
) error {
	t.Helper()

	return component.RunReporter(
		ctx,
		reporter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-reporter"),
		component.RunnerWithWorkflowID(workflowID),
		component.RunnerWithStorer("local", store),
	)
}

func TestRunReporter(t *testing.T) {
	var (
		ctrl, ctx    = gomock.WithContext(context.Background(), t)
		workflowID   = uuid.New()
		mockCtx      = gomock.AssignableToTypeOf(ctx)
		mockStore    = mocks.NewMockStorer(ctrl)
		mockReporter = mocks.NewMockReporter(ctrl)
		vulns        = make([]*ocsf.VulnerabilityFinding, 0)
	)

	t.Run("it should run a reporter correctly", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, workflowID).
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

		require.NoError(t, runReporterHelper(t, ctx, workflowID, mockReporter, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, workflowID).
				DoAndReturn(func(ctx context.Context, workflowID uuid.UUID) ([]*ocsf.VulnerabilityFinding, error) {
					cancel()
					return vulns, nil
				}),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
					<-ctx.Done()
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runReporterHelper(t, ctx, workflowID, mockReporter, mockStore))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		var errRead = errors.New("reader-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, workflowID).
				Return(nil, errRead),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runReporterHelper(t, ctx, workflowID, mockReporter, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when reporting errors", func(t *testing.T) {
		var errReporting = errors.New("reporting-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, workflowID).
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

		err := runReporterHelper(t, ctx, workflowID, mockReporter, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errReporting)
	})

	t.Run("it should return early when a panic is detected on reporting", func(t *testing.T) {
		var errReporting = errors.New("reporting-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, workflowID).
				Return(vulns, nil),
			mockReporter.
				EXPECT().
				Report(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
					panic(errReporting)
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runReporterHelper(t, ctx, workflowID, mockReporter, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errReporting)
	})
}
