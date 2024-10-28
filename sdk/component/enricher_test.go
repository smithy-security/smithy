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
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runEnricherHelper(
	t *testing.T,
	ctx context.Context,
	enricher component.Enricher,
	store component.Storer,
) error {
	t.Helper()

	return component.RunEnricher(
		ctx,
		enricher,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-enricher"),
		component.RunnerWithStorer("local", store),
	)
}

func TestRunEnricher(t *testing.T) {
	var (
		ctrl, ctx     = gomock.WithContext(context.Background(), t)
		mockCtx       = gomock.AssignableToTypeOf(ctx)
		mockStore     = mocks.NewMockStorer(ctrl)
		mockEnricher  = mocks.NewMockEnricher(ctrl)
		vulns         = make([]*ocsf.VulnerabilityFinding, 0, 2)
		enrichedVulns = make([]*ocsf.VulnerabilityFinding, 0, 2)
	)

	t.Run("it should run a enricher correctly and enrich out one finding", func(t *testing.T) {
		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				Return(enrichedVulns, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, enrichedVulns).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runEnricherHelper(t, ctx, mockEnricher, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
					cancel()
					return enrichedVulns, nil
				}),
			mockStore.
				EXPECT().
				Update(mockCtx, enrichedVulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
					<-ctx.Done()
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runEnricherHelper(t, ctx, mockEnricher, mockStore))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		var errRead = errors.New("reader-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(nil, errRead),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runEnricherHelper(t, ctx, mockEnricher, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when annotating errors", func(t *testing.T) {
		var errAnnotation = errors.New("annotator-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				Return(nil, errAnnotation),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runEnricherHelper(t, ctx, mockEnricher, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errAnnotation)
	})

	t.Run("it should return early when updating errors", func(t *testing.T) {
		var errUpdate = errors.New("update-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				Return(enrichedVulns, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, enrichedVulns).
				Return(errUpdate),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runEnricherHelper(t, ctx, mockEnricher, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUpdate)
	})

	t.Run("it should return early when a panic is detected on enriching", func(t *testing.T) {
		var errAnnotation = errors.New("annotator-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
					panic(errAnnotation)
					return enrichedVulns, nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runEnricherHelper(t, ctx, mockEnricher, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errAnnotation)
	})
}
