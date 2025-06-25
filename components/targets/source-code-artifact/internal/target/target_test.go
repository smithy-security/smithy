package target_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/target"
)

func TestNew(t *testing.T) {
	var (
		ctrl          = gomock.NewController(t)
		mockFetcher   = NewMockFetcher(ctrl)
		mockPersister = NewMockPersister(ctrl)
		mockExtractor = NewMockExtractor(ctrl)
		mockWriter    = NewMockMetadataWriter(ctrl)
		testCfg       = target.Config{
			ArchivePath:    "/path/to/archive.zip",
			SourceCodePath: "/path/to/source",
			ArtifactURL:    "https://example.com/artifact.zip",
		}
	)

	t.Run("successful creation", func(t *testing.T) {
		result, err := target.New(testCfg, mockFetcher, mockPersister, mockExtractor, mockWriter)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("nil fetcher", func(t *testing.T) {
		_, err := target.New(testCfg, nil, mockPersister, mockExtractor, mockWriter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fetcher cannot be nil")
	})

	t.Run("nil persister", func(t *testing.T) {
		_, err := target.New(testCfg, mockFetcher, nil, mockExtractor, mockWriter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "persister cannot be nil")
	})

	t.Run("nil extractor", func(t *testing.T) {
		_, err := target.New(testCfg, mockFetcher, mockPersister, nil, mockWriter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "extractor cannot be nil")
	})

	t.Run("nil writer", func(t *testing.T) {
		_, err := target.New(testCfg, mockFetcher, mockPersister, mockExtractor, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "writer cannot be nil")
	})
}

func TestSourceCodeTarget_Prepare(t *testing.T) {
	const (
		testArchivePath    = "/path/to/archive.zip"
		testSourceCodePath = "/path/to/source"
		testArtifactURL    = "https://example.com/artifact.zip"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var (
		ctrl          = gomock.NewController(t)
		mockFetcher   = NewMockFetcher(ctrl)
		mockPersister = NewMockPersister(ctrl)
		mockExtractor = NewMockExtractor(ctrl)
		mockWriter    = NewMockMetadataWriter(ctrl)
		fetchErr      = errors.New("fetch error")
		persistErr    = errors.New("persist error")
		extractErr    = errors.New("extract error")
		metadataErr   = errors.New("metadata error")
		mockReader    = io.NopCloser(strings.NewReader("test data"))
		testCfg       = target.Config{
			ArchivePath:    testArchivePath,
			SourceCodePath: testSourceCodePath,
			ArtifactURL:    testArtifactURL,
		}
	)

	testTarget, err := target.New(testCfg, mockFetcher, mockPersister, mockExtractor, mockWriter)
	require.NoError(t, err)

	t.Run("successful prepare", func(t *testing.T) {
		gomock.InOrder(
			mockFetcher.EXPECT().FetchArtifact(ctx).Return(mockReader, nil),
			mockPersister.EXPECT().Persist(ctx, testArchivePath, mockReader).Return(nil),
			mockExtractor.EXPECT().ExtractArtifact(ctx, testArchivePath, testSourceCodePath).Return(nil),
			mockWriter.EXPECT().WriteMetadata(ctx).Return(nil),
		)

		err = testTarget.Prepare(ctx)
		require.NoError(t, err)
	})

	t.Run("fetch artifact error", func(t *testing.T) {
		mockFetcher.EXPECT().FetchArtifact(ctx).Return(nil, fetchErr)

		err = testTarget.Prepare(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, fetchErr)
		assert.Contains(t, err.Error(), "could not fetch artifact")
	})

	t.Run("persist artifact error", func(t *testing.T) {
		gomock.InOrder(
			mockFetcher.EXPECT().FetchArtifact(ctx).Return(mockReader, nil),
			mockPersister.EXPECT().Persist(ctx, testArchivePath, mockReader).Return(persistErr),
		)

		err = testTarget.Prepare(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, persistErr)
		assert.Contains(t, err.Error(), "could not persist artifact")
	})

	t.Run("extract artifact error", func(t *testing.T) {
		gomock.InOrder(
			mockFetcher.EXPECT().FetchArtifact(ctx).Return(mockReader, nil),
			mockPersister.EXPECT().Persist(ctx, testArchivePath, mockReader).Return(nil),
			mockExtractor.EXPECT().ExtractArtifact(ctx, testArchivePath, testSourceCodePath).Return(extractErr),
		)

		err = testTarget.Prepare(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, extractErr)
		assert.Contains(t, err.Error(), "could not extract artifact")
	})

	t.Run("write metadata error", func(t *testing.T) {
		gomock.InOrder(
			mockFetcher.EXPECT().FetchArtifact(ctx).Return(mockReader, nil),
			mockPersister.EXPECT().Persist(ctx, testArchivePath, mockReader).Return(nil),
			mockExtractor.EXPECT().ExtractArtifact(ctx, testArchivePath, testSourceCodePath).Return(nil),
			mockWriter.EXPECT().WriteMetadata(ctx).Return(metadataErr),
		)

		err = testTarget.Prepare(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, metadataErr)
		assert.Contains(t, err.Error(), "could not persist metadata")
	})
}
