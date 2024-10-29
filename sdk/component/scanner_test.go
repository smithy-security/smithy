package component_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/sdk/component/internal/mocks"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

func runScannerHelper(
	t *testing.T,
	ctx context.Context,
	reporter component.Scanner,
	storer component.Storer,
) error {
	t.Helper()

	return component.RunScanner(
		ctx,
		reporter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-scanner"),
		component.RunnerWithStorer("local", storer),
	)
}

func TestRunScanner(t *testing.T) {
	var (
		ctrl, ctx   = gomock.WithContext(context.Background(), t)
		mockCtx     = gomock.AssignableToTypeOf(ctx)
		mockStore   = mocks.NewMockStorer(ctrl)
		mockScanner = mocks.NewMockScanner(ctrl)
		vulns       = make([]*ocsf.VulnerabilityFinding, 2)
	)

	t.Run("it should run a scanner correctly", func(t *testing.T) {
		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				Return(vulns, nil),
			mockStore.
				EXPECT().
				Validate(vulns[0]).
				Return(nil),
			mockStore.
				EXPECT().
				Validate(vulns[1]).
				Return(nil),
			mockStore.
				EXPECT().
				Write(mockCtx, vulns).
				Return(nil),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runScannerHelper(t, ctx, mockScanner, mockStore))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)

		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				DoAndReturn(func(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
					cancel()
					return vulns, nil
				}),
			mockStore.
				EXPECT().
				Validate(vulns[0]).
				Return(nil),
			mockStore.
				EXPECT().
				Validate(vulns[1]).
				Return(nil),
			mockStore.
				EXPECT().
				Write(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
					<-ctx.Done()
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		require.NoError(t, runScannerHelper(t, ctx, mockScanner, mockStore))
	})

	t.Run("it should return early when transforming errors", func(t *testing.T) {
		var errTransform = errors.New("transformer-is-sad")

		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				Return(nil, errTransform),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runScannerHelper(t, ctx, mockScanner, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errTransform)
	})

	t.Run("it should return early when validation errors", func(t *testing.T) {
		var errValidate = errors.New("validate-is-sad")

		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				Return(vulns, nil),
			mockStore.
				EXPECT().
				Validate(vulns[0]).
				Return(errValidate),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runScannerHelper(t, ctx, mockScanner, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errValidate)
	})

	t.Run("it should return early when store errors", func(t *testing.T) {
		var errStore = errors.New("store-is-sad")

		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				Return(vulns, nil),
			mockStore.
				EXPECT().
				Validate(vulns[0]).
				Return(nil),
			mockStore.
				EXPECT().
				Validate(vulns[1]).
				Return(nil),
			mockStore.
				EXPECT().
				Write(mockCtx, vulns).
				Return(errStore),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runScannerHelper(t, ctx, mockScanner, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errStore)
	})

	t.Run("it should return early when a panic is detected on storing", func(t *testing.T) {
		var errStore = errors.New("store-is-sad")

		gomock.InOrder(
			mockScanner.
				EXPECT().
				Transform(mockCtx).
				Return(vulns, nil),
			mockStore.
				EXPECT().
				Validate(vulns[0]).
				Return(nil),
			mockStore.
				EXPECT().
				Validate(vulns[1]).
				Return(nil),
			mockStore.
				EXPECT().
				Write(mockCtx, vulns).
				DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
					panic(errStore)
					return nil
				}),
			mockStore.
				EXPECT().
				Close(mockCtx).
				Return(nil),
		)

		err := runScannerHelper(t, ctx, mockScanner, mockStore)
		require.Error(t, err)
		assert.ErrorIs(t, err, errStore)
	})
}
