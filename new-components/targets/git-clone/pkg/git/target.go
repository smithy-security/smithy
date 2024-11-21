package git

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/jonboulle/clockwork"

	"github.com/smithy-security/smithy/sdk/component"
)

type (
	// Cloner is the contract for cloning repositories.
	Cloner interface {
		Clone(ctx context.Context) (*Repository, error)
	}

	gitCloneTarget struct {
		conf   *Conf
		cloner Cloner
		fs     billy.Filesystem
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

// WithCloner allows customising the default cloner. Mainly used for testing.
func WithCloner(cloner Cloner) gitCloneTargetOption {
	return func(gct *gitCloneTarget) error {
		if cloner == nil {
			return errors.New("invalid nil cloner")
		}
		gct.cloner = cloner
		return nil
	}
}

// WithFS allows customising the default filesystem manager. Mainly used for testing.
func WithFS(fs billy.Filesystem) gitCloneTargetOption {
	return func(gct *gitCloneTarget) error {
		if fs == nil {
			return errors.New("invalid nil filesystem")
		}
		gct.fs = fs
		return nil
	}
}

// NewTarget returns a new git clone target.
func NewTarget(conf *Conf, opts ...gitCloneTargetOption) (*gitCloneTarget, error) {
	gt := gitCloneTarget{
		conf:  conf,
		fs:    osfs.New(conf.ClonePath),
		clock: clockwork.NewRealClock(),
	}

	for _, opt := range opts {
		if err := opt(&gt); err != nil {
			return nil, errors.Errorf("could not apply option: %w", err)
		}
	}

	if gt.cloner == nil {
		var err error
		gt.cloner, err = NewManager(gt.conf)
		if err != nil {
			return nil, errors.Errorf("could not create cloner: %w", err)
		}
	}

	return &gt, nil
}

// Prepare clones a repository in the desired path.
func (g *gitCloneTarget) Prepare(ctx context.Context) error {
	var (
		startTime = g.clock.Now()
		logger    = component.
				LoggerFromContext(ctx).
				With(slog.String("clone_start_time", startTime.Format(time.RFC3339))).
				With(slog.String("repo_url", g.conf.RepoURL)).
				With(slog.String("reference", g.conf.Reference)).
				With(slog.String("clone_path", g.conf.ClonePath))
	)

	logger.Debug("checking if clone path exists...")

	if _, err := g.fs.Stat(g.conf.ClonePath); err != nil {
		if os.IsNotExist(err) {
			logger.Debug("clone path does not exist, creating directory...")
			if err := g.fs.MkdirAll(g.conf.ClonePath, os.ModePerm); err != nil {
				return errors.Errorf("failed to create clone path %s: %v", g.conf.ClonePath, err)
			}
			logger.Debug("successfully created directory")
		} else {
			return errors.Errorf("could not check if clone path exists: %w", err)
		}
	}

	logger.Debug("preparing to clone repository...")

	if _, err := g.cloner.Clone(ctx); err != nil {
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
	return nil
}
