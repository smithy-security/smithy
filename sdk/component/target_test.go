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
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl = gomock.NewController(t)
	)

	t.Run("it should run a target correctly", func(t *testing.T) {
		mockTarget := mocks.NewMockTarget(ctrl)

		mockTarget.
			EXPECT().
			Prepare(gomock.Any()).
			Return(nil)
		mockTarget.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runTargetHelper(t, ctx, mockTarget))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		mockTarget := mocks.NewMockTarget(ctrl)

		mockTarget.
			EXPECT().
			Prepare(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			})
		mockTarget.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runTargetHelper(t, ctx, mockTarget))
	})

	t.Run("it should return early when prepare errors", func(t *testing.T) {
		var (
			errPrepare = errors.New("prepare-is-sad")
			mockTarget = mocks.NewMockTarget(ctrl)
		)

		mockTarget.
			EXPECT().
			Prepare(gomock.Any()).
			Return(errPrepare)
		mockTarget.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runTargetHelper(t, ctx, mockTarget)
		require.Error(t, err)
		assert.ErrorIs(t, err, errPrepare)
	})

	t.Run("it should keep shutting down the application when a panic is detected during close", func(t *testing.T) {
		mockTarget := mocks.NewMockTarget(ctrl)

		mockTarget.
			EXPECT().
			Prepare(gomock.Any()).
			Return(nil)
		mockTarget.
			EXPECT().
			Close(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errors.New("close-is-sad"))
				return nil
			})

		err := runTargetHelper(t, ctx, mockTarget)
		require.NoError(t, err)
	})

	t.Run("it should return early when a panic is detected on prepare", func(t *testing.T) {
		var (
			errPrepare = errors.New("prepare-is-sad")
			mockTarget = mocks.NewMockTarget(ctrl)
		)

		mockTarget.
			EXPECT().
			Prepare(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errPrepare)
				return nil
			})
		mockTarget.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runTargetHelper(t, ctx, mockTarget)
		require.Error(t, err)
		assert.ErrorIs(t, err, errPrepare)
	})
}
