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

func runEnricherHelper(t *testing.T, ctx context.Context, enricher component.Enricher) error {
	t.Helper()

	return component.RunEnricher(
		ctx,
		enricher,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-enricher"),
	)
}

func TestRunEnricher(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl          = gomock.NewController(t)
		vulns         = make([]*ocsf.VulnerabilityFinding, 0, 2)
		enrichedVulns = make([]*ocsf.VulnerabilityFinding, 0, 2)
	)

	t.Run("it should run a enricher correctly and enrich out one finding", func(t *testing.T) {
		mockEnricher := mocks.NewMockEnricher(ctrl)
		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			Return(enrichedVulns, nil)
		mockEnricher.
			EXPECT().
			Update(gomock.Any(), enrichedVulns).
			Return(nil)
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runEnricherHelper(t, ctx, mockEnricher))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockEnricher := mocks.NewMockEnricher(ctrl)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
				cancel()
				return enrichedVulns, nil
			})
		mockEnricher.
			EXPECT().
			Update(gomock.Any(), enrichedVulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				<-ctx.Done()
				return nil
			})
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runEnricherHelper(t, ctx, mockEnricher))
	})

	t.Run("it should return early when reading errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errRead      = errors.New("reader-is-sad")
			mockEnricher = mocks.NewMockEnricher(ctrl)
		)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(nil, errRead)
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runEnricherHelper(t, ctx, mockEnricher)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when annotating errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errAnnotation = errors.New("annotator-is-sad")
			mockEnricher  = mocks.NewMockEnricher(ctrl)
		)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			Return(nil, errAnnotation)
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runEnricherHelper(t, ctx, mockEnricher)
		require.Error(t, err)
		assert.ErrorIs(t, err, errAnnotation)
	})

	t.Run("it should return early when updating errors", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errUpdate    = errors.New("update-is-sad")
			mockEnricher = mocks.NewMockEnricher(ctrl)
		)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			Return(enrichedVulns, nil)
		mockEnricher.
			EXPECT().
			Update(gomock.Any(), enrichedVulns).
			Return(errUpdate)
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runEnricherHelper(t, ctx, mockEnricher)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUpdate)
	})

	t.Run("it should keep shutting down the application when a panic is detected during close", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockEnricher := mocks.NewMockEnricher(ctrl)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			Return(enrichedVulns, nil)
		mockEnricher.
			EXPECT().
			Update(gomock.Any(), enrichedVulns).
			Return(nil)
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errors.New("close-is-sad"))
				return nil
			})

		require.NoError(t, runEnricherHelper(t, ctx, mockEnricher))
	})

	t.Run("it should return early when a panic is detected on enriching", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		var (
			errAnnotation = errors.New("annotator-is-sad")
			mockEnricher  = mocks.NewMockEnricher(ctrl)
		)

		mockEnricher.
			EXPECT().
			Read(gomock.Any()).
			Return(vulns, nil)
		mockEnricher.
			EXPECT().
			Annotate(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
				panic(errAnnotation)
				return enrichedVulns, nil
			})
		mockEnricher.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runEnricherHelper(t, ctx, mockEnricher)
		require.Error(t, err)
		assert.ErrorIs(t, err, errAnnotation)
	})
}
