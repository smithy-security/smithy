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

	// Persister abstracts artifact persistence.
	Persister interface {
		Persist(ctx context.Context, dest string, ioReader io.Reader) error
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

	// SourceCodeTarget is a target that downloads an artefact and extracts it
	// in order for it to be scanned
	SourceCodeTarget struct {
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
) (SourceCodeTarget, error) {
	switch {
	case fetcher == nil:
		return SourceCodeTarget{}, errors.New("fetcher cannot be nil")
	case persister == nil:
		return SourceCodeTarget{}, errors.New("persister cannot be nil")
	case extractor == nil:
		return SourceCodeTarget{}, errors.New("extractor cannot be nil")
	case writer == nil:
		return SourceCodeTarget{}, errors.New("writer cannot be nil")
	}

	return SourceCodeTarget{
		cfg:       cfg,
		fetcher:   fetcher,
		persister: persister,
		extractor: extractor,
		writer:    writer,
	}, nil
}

// Prepare fetches a source code bundle from a selected source.
func (s SourceCodeTarget) Prepare(ctx context.Context) error {
	l := logger.
		LoggerFromContext(ctx).
		With(
			slog.String("source_code_path", s.cfg.SourceCodePath),
			slog.String("archive_path", s.cfg.ArchivePath),
			slog.String("artifact_url", s.cfg.ArtifactURL),
		)
	l.Debug("executing prepare step...")

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
