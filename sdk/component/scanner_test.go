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

func runScannerHelper(t *testing.T, ctx context.Context, reporter component.Scanner) error {
	t.Helper()

	return component.RunScanner(
		ctx,
		reporter,
		component.RunnerWithLogger(component.NewNoopLogger()),
		component.RunnerWithComponentName("sample-scanner"),
	)
}

func TestRunScanner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl     = gomock.NewController(t)
		vulns    = make([]*ocsf.VulnerabilityFinding, 2)
		rawVulns = make([]component.Unmarshaler, 2)
	)

	t.Run("it should run a scanner correctly", func(t *testing.T) {
		mockScanner := mocks.NewMockScanner(ctrl)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[0], nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[1], nil)
		mockScanner.
			EXPECT().
			Store(gomock.Any(), vulns).
			Return(nil)
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runScannerHelper(t, ctx, mockScanner))
	})

	t.Run("it should return early when the context is cancelled", func(t *testing.T) {
		ctx, cancel = context.WithCancel(ctx)

		mockScanner := mocks.NewMockScanner(ctrl)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[0], nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			DoAndReturn(func(ctx context.Context, rawVuln component.Unmarshaler) (*ocsf.VulnerabilityFinding, error) {
				cancel()
				return vulns[1], nil
			})
		mockScanner.
			EXPECT().
			Store(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				<-ctx.Done()
				return nil
			})
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		require.NoError(t, runScannerHelper(t, ctx, mockScanner))
	})

	t.Run("it should return early when scanning errors", func(t *testing.T) {
		var (
			errRead     = errors.New("scanner-is-sad")
			mockScanner = mocks.NewMockScanner(ctrl)
		)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(nil, errRead)
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runScannerHelper(t, ctx, mockScanner)
		require.Error(t, err)
		assert.ErrorIs(t, err, errRead)
	})

	t.Run("it should return early when transforming errors", func(t *testing.T) {
		var (
			errTransform = errors.New("transformer-is-sad")
			mockScanner  = mocks.NewMockScanner(ctrl)
		)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(nil, errTransform)
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runScannerHelper(t, ctx, mockScanner)
		require.Error(t, err)
		assert.ErrorIs(t, err, errTransform)
	})

	t.Run("it should return early when store errors", func(t *testing.T) {
		var (
			errStore    = errors.New("store-is-sad")
			mockScanner = mocks.NewMockScanner(ctrl)
		)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[0], nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[1], nil)
		mockScanner.
			EXPECT().
			Store(gomock.Any(), vulns).
			Return(errStore)
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runScannerHelper(t, ctx, mockScanner)
		require.Error(t, err)
		assert.ErrorIs(t, err, errStore)
	})

	t.Run("it should keep shutting down the application when a panic is detected during close", func(t *testing.T) {
		mockScanner := mocks.NewMockScanner(ctrl)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[0], nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[1], nil)
		mockScanner.
			EXPECT().
			Store(gomock.Any(), vulns).
			Return(nil)
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			DoAndReturn(func(ctx context.Context) error {
				panic(errors.New("close-is-sad"))
				return nil
			})

		err := runScannerHelper(t, ctx, mockScanner)
		require.NoError(t, err)
	})

	t.Run("it should return early when a panic is detected on storing", func(t *testing.T) {
		var (
			errStore    = errors.New("store-is-sad")
			mockScanner = mocks.NewMockScanner(ctrl)
		)

		mockScanner.
			EXPECT().
			Scan(gomock.Any()).
			Return(rawVulns, nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[0], nil)
		mockScanner.
			EXPECT().
			Transform(gomock.Any(), (component.Unmarshaler)(nil)).
			Return(vulns[1], nil)
		mockScanner.
			EXPECT().
			Store(gomock.Any(), vulns).
			DoAndReturn(func(ctx context.Context, vulns []*ocsf.VulnerabilityFinding) error {
				panic(errStore)
				return nil
			})
		mockScanner.
			EXPECT().
			Close(gomock.Any()).
			Return(nil)

		err := runScannerHelper(t, ctx, mockScanner)
		require.Error(t, err)
		assert.ErrorIs(t, err, errStore)
	})
}
