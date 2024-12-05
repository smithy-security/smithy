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
	"github.com/smithy-security/smithy/sdk/component/uuid"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runEnricherHelper(
	t *testing.T,
	ctx context.Context,
	instanceID uuid.UUID,
	enricher component.Enricher,
	store component.Storer,
) error {
	t.Helper()

	return component.RunEnricher(
		ctx,
		enricher,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-enricher"),
		component.RunnerWithInstanceID(instanceID),
		component.RunnerWithStorer(store),
	)
}

func TestRunEnricher(t *testing.T) {
	var (
		ctrl, ctx     = gomock.WithContext(context.Background(), t)
		instanceID    = uuid.New()
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
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				Return(enrichedVulns, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, enrichedVulns).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				DoAndReturn(
					func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
						cancel()
						return enrichedVulns, nil
					}),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, enrichedVulns).
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

		require.NoError(t, runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore))
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

		err := runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when annotating errors", func(t *testing.T) {
		var errAnnotation = errors.New("annotator-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
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

		require.ErrorIs(t, runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore), errAnnotation)
	})

	t.Run("it should return early when updating errors", func(t *testing.T) {
		var errUpdate = errors.New("update-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				Return(enrichedVulns, nil),
			mockStore.
				EXPECT().
				Update(mockCtx, instanceID, enrichedVulns).
				Return(errUpdate),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore), errUpdate)
	})

	t.Run("it should return early when a panic is detected on enriching", func(t *testing.T) {
		var errAnnotation = errors.New("annotator-is-sad")

		gomock.InOrder(
			mockStore.
				EXPECT().
				Read(mockCtx, instanceID).
				Return(vulns, nil),
			mockEnricher.
				EXPECT().
				Annotate(mockCtx, vulns).
				DoAndReturn(
					func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
						panic(errAnnotation)
						return enrichedVulns, nil
					}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.ErrorIs(t, runEnricherHelper(t, ctx, instanceID, mockEnricher, mockStore), errAnnotation)
	})
}
