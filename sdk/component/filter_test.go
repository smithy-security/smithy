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
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runFilterHelper(
	t *testing.T,
	ctx context.Context,
	instanceID uuid.UUID,
	filter component.Filter,
	store component.Storer,
) error {
	t.Helper()

	return component.RunFilter(
		ctx,
		filter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-filter"),
		component.RunnerWithInstanceID(instanceID),
		component.RunnerWithStorer(store),
	)
}

func TestRunFilter(t *testing.T) {
	var (
		ctrl, ctx     = gomock.WithContext(context.Background(), t)
		instanceID    = uuid.New()
		mockCtx       = gomock.AssignableToTypeOf(ctx)
		mockStore     = mocks.NewMockStorer(ctrl)
		mockFilter    = mocks.NewMockFilter(ctrl)
		vulns         = make([]*ocsf.VulnerabilityFinding, 0, 2)
		filteredVulns = make([]*ocsf.VulnerabilityFinding, 0, 1)
	)

	t.Run("it should run a filter correctly and filter out one finding", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				Return(filteredVulns, true, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, filteredVulns).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore))
	})

	t.Run("it should run a filter correctly and return early as no filtering was done", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				Return(nil, false, nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
					cancel()
					return filteredVulns, true, nil
				}),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, filteredVulns).
				DoAndReturn(
					func(
						ctx context.Context,
						instanceID uuid.UUID,
						vulns []*ocsf.VulnerabilityFinding,
					) error {
						<-ctx.Done()
						return nil
					}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore))
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

		require.ErrorIs(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore), errRead)
	})

	t.Run("it should return early when filtering errors", func(t *testing.T) {
		var errFilter = errors.New("filter-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				Return(nil, false, errFilter),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore), errFilter)
	})

	t.Run("it should return early when updating errors", func(t *testing.T) {
		var errUpdate = errors.New("update-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				Return(filteredVulns, true, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, filteredVulns).
				Return(errUpdate),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore), errUpdate)
	})

	t.Run("it should return early when a panic is detected on filtering", func(t *testing.T) {
		var errFilter = errors.New("filter-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockFilter.
				EXPECT().
				Filter(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
					panic(errFilter)
					return filteredVulns, true, nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runFilterHelper(t, ctx, instanceID, mockFilter, mockStore), errFilter)
	})
}
