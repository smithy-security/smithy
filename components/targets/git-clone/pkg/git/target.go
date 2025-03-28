package git

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
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

// NewTarget returns a new git clone target.
func NewTarget(conf *Conf, opts ...gitCloneTargetOption) (*gitCloneTarget, error) {
	gt := gitCloneTarget{
		conf:  conf,
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
				With(slog.String("reference", g.conf.Reference))
	)

	logger.Debug("preparing to clone repository...")
	if _, err := g.cloner.Clone(ctx); err != nil {
		if errors.Is(err, git.ErrRepositoryAlreadyExists) {
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
	return nil
}
