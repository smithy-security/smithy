package target

import (
	"context"
	"io"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/targets/source-code-artifact/internal/reader"
)

type (
	// Fetcher abstracts artifact fetching.
	Fetcher interface {
		FetchArtifact(ctx context.Context) (io.ReadCloser, error)
	}

	// Persister abstracts artifact persistance.
	Persister interface {
		Persist(ctx context.Context, dest string, reader io.Reader) error
	}

	// Extractor abstracts artifact extraction.
	Extractor interface {
		ExtractArtifact(ctx context.Context, sourcePath, destPath string) error
	}

	// MetadataWriter abstracts metadata writing.
	MetadataWriter interface {
		WriteMetadata(ctx context.Context) error
	}

	// Config contains the target config.
	Config struct {
		ArchivePath    string
		SourceCodePath string
		ArtifactURL    string
	}

	sourceCodeTarget struct {
		cfg       Config
		fetcher   Fetcher
		extractor Extractor
		persister Persister
		writer    MetadataWriter
	}
)

// New returns a new target.
func New(
	cfg Config,
	fetcher Fetcher,
	persister Persister,
	extractor Extractor,
	writer MetadataWriter,
) (sourceCodeTarget, error) {
	switch {
	case fetcher == nil:
		return sourceCodeTarget{}, errors.New("fetcher cannot be nil")
	case persister == nil:
		return sourceCodeTarget{}, errors.New("persister cannot be nil")
	case extractor == nil:
		return sourceCodeTarget{}, errors.New("extractor cannot be nil")
	case writer == nil:
		return sourceCodeTarget{}, errors.New("writer cannot be nil")
	}

	return sourceCodeTarget{
		cfg:       cfg,
		fetcher:   fetcher,
		persister: persister,
		extractor: extractor,
		writer:    writer,
	}, nil
}

// Prepare fetches a source code bundle from a selected source.
func (s sourceCodeTarget) Prepare(ctx context.Context) error {
	l := logger.
		LoggerFromContext(ctx).
		With(
			slog.String("source_code_path", s.cfg.SourceCodePath),
			slog.String("archive_path", s.cfg.ArchivePath),
		)
	l.Debug("executing Prepare step...")

	l.Debug("fetching artifact...")
	artifactReader, err := s.fetcher.FetchArtifact(ctx)
	if err != nil {
		return errors.Errorf("could not fetch artifact: %w", err)
	}
	l.Debug("successfully fetched artifact!")
	defer reader.CloseReader(ctx, artifactReader)

	l.Debug("persisting artifact...")
	if err := s.persister.Persist(ctx, s.cfg.ArchivePath, artifactReader); err != nil {
		return errors.Errorf("could not persist artifact at '%s': %w", s.cfg.ArchivePath, err)
	}
	l.Debug("successfully persisted artifact!")

	l.Debug("preparing to extract artifact...")
	if err := s.extractor.ExtractArtifact(ctx, s.cfg.ArchivePath, s.cfg.SourceCodePath); err != nil {
		return errors.Errorf("could not extract artifact: %w", err)
	}
	l.Debug("successfully extracted artifact!")

	l.Debug("preparing to persist metadata...")
	if err := s.writer.WriteMetadata(ctx); err != nil {
		return errors.Errorf("could not persist metadata: %w", err)
	}
	l.Debug("successfully persisted metadata!")

	l.Debug("Prepare step completed!")
	return nil
}
