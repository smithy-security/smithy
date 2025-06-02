package target

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/targets/git-clone/pkg/git"
)

type (
	// Cloner is the contract for cloning repositories.
	Cloner interface {
		Clone(ctx context.Context) (*git.Repository, error)
	}

	gitCloneTarget struct {
		cloner Cloner
		conf   *git.Conf
		clock  clockwork.Clock
	}

	gitCloneTargetOption func(*gitCloneTarget) error
)

// WithClock allows customising the default clock. Mainly used for testing.
func WithClock(clock clockwork.Clock) gitCloneTargetOption {
	return func(gct *gitCloneTarget) error {
		if clock == nil {
			return errors.New("invalid nil clock")
		}
		gct.clock = clock
		return nil
	}
}

// NewTarget returns a new git clone target.
func NewTarget(conf *git.Conf, cloner Cloner, opts ...gitCloneTargetOption) (*gitCloneTarget, error) {
	if cloner == nil {
		return nil, errors.New("invalid nil cloner")
	}

	gt := gitCloneTarget{
		cloner: cloner,
		conf:   conf,
		clock:  clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&gt); err != nil {
			return nil, errors.Errorf("could not apply option: %w", err)
		}
	}

	return &gt, nil
}

// Prepare clones a repository in the desired path.
// It also adds target metadata and potential diff into the provided paths.
func (g *gitCloneTarget) Prepare(ctx context.Context) error {
	var (
		startTime = g.clock.Now()
		logger    = component.
				LoggerFromContext(ctx).
				With(slog.String("clone_start_time", startTime.Format(time.RFC3339))).
				With(slog.String("repo_url", g.conf.RepoURL)).
				With(slog.String("reference", g.conf.Reference)).
				With(slog.String("reference", g.conf.Reference)).
				With(slog.String("metadata_path", g.conf.TargetMetadataPath)).
				With(slog.String("raw_diff_path", g.conf.RawDiffPath))
	)

	ctx = component.ContextWithLogger(ctx, logger)
	logger.Debug("preparing to clone repository...")
	repo, err := g.cloner.Clone(ctx)
	if err != nil {
		if errors.Is(err, gogit.ErrRepositoryAlreadyExists) {
			logger.Debug("clone path already exists, skipping clone")
			return nil
		}
		return errors.Errorf("could not clone repository: %w", err)
	}

	var (
		endTime       = g.clock.Now()
		cloneDuration = endTime.Sub(startTime)
	)

	logger.
		Debug(
			"successfully cloned repository",
			slog.String("clone_end_time", endTime.Format(time.RFC3339)),
			slog.String("clone_duration", cloneDuration.String()),
		)

	logger.Debug("preparing to write metadata...")
	if err := g.prepareMetadata(ctx); err != nil {
		return errors.Errorf("could not prepare metadata: %w", err)
	}
	logger.Debug("successfully wrote metadata")

	logger.Debug("preparing to write diff...")
	if err := g.prepareDiff(ctx, repo); err != nil {
		return errors.Errorf("could not prepare diff: %w", err)
	}
	logger.Debug("successfully wrote diff if needed")

	logger.Debug("git-cloner completed, returning")
	return nil
}

func (g *gitCloneTarget) prepareMetadata(ctx context.Context) error {
	logger := component.LoggerFromContext(ctx)
	logger.Debug("preparing to write target metadata...")

	if g.conf.TargetMetadataPath == "" {
		logger.Warn("target metadata path is empty, skipping writing source metadata")
		return nil
	}

	fd, err := os.OpenFile(g.conf.TargetMetadataPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return errors.Errorf("could not open file to report clone metadata: %w", err)
	}

	parsedURL, err := url.Parse(g.conf.RepoURL)
	if err != nil {
		return errors.Errorf("could not parse clone URL of the repository: %w", err)
	}

	if parsedURL.User != nil {
		parsedURL.User = nil
	}

	// remove the .git suffix to ensure everything is normalised
	parsedURL.Path = strings.TrimRight(parsedURL.Path, ".git")

	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
		SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
			RepositoryUrl: parsedURL.String(),
			Reference:     g.conf.Reference,
		},
	}

	marshaledDataSource, err := protojson.Marshal(dataSource)
	if err != nil {
		return errors.Errorf("could not marshal data source into JSON: %w", err)
	}

	_, err = fd.Write(marshaledDataSource)
	if err != nil {
		return errors.Errorf("could not write marshaled data source to file: %w", err)
	}

	logger.Debug(
		"wrote the following content for target metadata",
		slog.String("content", string(marshaledDataSource)),
	)

	return fd.Close()
}

func (g *gitCloneTarget) prepareDiff(ctx context.Context, repo *git.Repository) error {
	if repo == nil || repo.Repo == nil {
		return nil
	}

	logger := component.LoggerFromContext(ctx)
	logger.Debug("preparing to compute diff...")

	diff, err := repo.GetDiff(ctx)
	switch {
	case err != nil:
		return errors.Errorf("could not get repository diff: %w", err)
	case diff == "":
		logger.Debug("no diff found, skipping writing raw diff")
		return nil
	}

	logger.Debug("computed diff", slog.String("raw_diff", diff))
	fd, err := os.OpenFile(g.conf.RawDiffPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return errors.Errorf("could not open file to report raw diff: %w", err)
	}

	if _, err := fd.WriteString(diff); err != nil {
		return errors.Errorf("could not write raw diff to file: %w", err)
	}

	return fd.Close()
}
