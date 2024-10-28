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
)

func runTargetHelper(t *testing.T, ctx context.Context, target component.Target) error {
	t.Helper()

	return component.RunTarget(
		ctx,
		target,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-target"),
	)
}

func TestRunTarget(t *testing.T) {
	var (
		ctrl, ctx  = gomock.WithContext(context.Background(), t)
		mockCtx    = gomock.AssignableToTypeOf(ctx)
		mockTarget = mocks.NewMockTarget(ctrl)
	)

	t.Run("it should run a target correctly", func(t *testing.T) {
		mockTarget.
			EXPECT().
			Prepare(mockCtx).
			Return(nil)
		require.NoError(t, runTargetHelper(t, ctx, mockTarget))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		mockTarget.
			EXPECT().
			Prepare(mockCtx).
			DoAndReturn(func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			})

		require.NoError(t, runTargetHelper(t, ctx, mockTarget))
	})

	t.Run("it should return an error when prepare errors", func(t *testing.T) {
		var errPrepare = errors.New("prepare-is-sad")

		mockTarget.
			EXPECT().
			Prepare(mockCtx).
			Return(errPrepare)

		err := runTargetHelper(t, ctx, mockTarget)
		require.Error(t, err)
		assert.ErrorIs(t, err, errPrepare)
	})

	t.Run("it should return early an error when a panic is detected on prepare", func(t *testing.T) {
		var errPrepare = errors.New("prepare-is-sad")

		mockTarget.
			EXPECT().
			Prepare(mockCtx).
			DoAndReturn(func(ctx context.Context) error {
				panic(errPrepare)
				return nil
			})

		err := runTargetHelper(t, ctx, mockTarget)
		require.Error(t, err)
		assert.ErrorIs(t, err, errPrepare)
	})
}
