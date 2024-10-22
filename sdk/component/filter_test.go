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

func runFilterHelper(t *testing.T, ctx context.Context, filter component.Filter) error {
	t.Helper()

	return component.RunFilter(
		ctx,
		filter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-filter"),
	)
}

func TestRunFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl          = gomock.NewController(t)
		vulns         = make([]*ocsf.VulnerabilityFinding, 0, 2)
		filteredVulns = make([]*ocsf.VulnerabilityFinding, 0, 1)
	)

	t.Run("it should run a filter correctly and filter out one finding", func(t *testing.T) {
		mockFilter := mocks.NewMockFilter(ctrl)
		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			Return(filteredVulns, true, nil)
		mockFilter.
			EXPECT().
			Update(gomock.Any(), filteredVulns).
			Return(nil)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runFilterHelper(t, ctx, mockFilter))
	})

	t.Run("it should run a filter correctly and return early as no filtering was done", func(t *testing.T) {
		mockFilter := mocks.NewMockFilter(ctrl)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			Return(nil, false, nil)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runFilterHelper(t, ctx, mockFilter))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockFilter := mocks.NewMockFilter(ctrl)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
				cancel()
				return filteredVulns, true, nil
			})
		mockFilter.
			EXPECT().
			Update(gomock.Any(), filteredVulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				<-ctx.Done()
				return nil
			})
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runFilterHelper(t, ctx, mockFilter))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errRead    = errors.New("reader-is-sad")
			mockFilter = mocks.NewMockFilter(ctrl)
		)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(nil, errRead)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runFilterHelper(t, ctx, mockFilter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when filtering errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errFilter  = errors.New("filter-is-sad")
			mockFilter = mocks.NewMockFilter(ctrl)
		)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			Return(nil, false, errFilter)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runFilterHelper(t, ctx, mockFilter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errFilter)
	})

	t.Run("it should return early when updating errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errUpdate  = errors.New("update-is-sad")
			mockFilter = mocks.NewMockFilter(ctrl)
		)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			Return(filteredVulns, true, nil)
		mockFilter.
			EXPECT().
			Update(gomock.Any(), filteredVulns).
			Return(errUpdate)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runFilterHelper(t, ctx, mockFilter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUpdate)
	})

	t.Run("it should keep shutting down the application when a panic is detected during close", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockFilter := mocks.NewMockFilter(ctrl)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			Return(filteredVulns, true, nil)
		mockFilter.
			EXPECT().
			Update(gomock.Any(), filteredVulns).
			Return(nil)
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errors.New("close-is-sad"))
				return nil
			})

		require.NoError(t, runFilterHelper(t, ctx, mockFilter))
	})

	t.Run("it should return early when a panic is detected on filtering", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errFilter  = errors.New("filter-is-sad")
			mockFilter = mocks.NewMockFilter(ctrl)
		)

		mockFilter.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockFilter.
			EXPECT().
			Filter(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
				panic(errFilter)
				return filteredVulns, true, nil
			})
		mockFilter.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runFilterHelper(t, ctx, mockFilter)
		require.Error(t, err)
		assert.ErrorIs(t, err, errFilter)
	})
}
