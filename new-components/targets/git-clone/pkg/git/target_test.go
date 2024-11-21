package git_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/targets/git-clone/pkg/git"
)

type testCloner struct {
	err  error
	repo *git.Repository
}

func (tc *testCloner) setErr(err error) {
	tc.err = err
}

func (tc *testCloner) setRepo(repo *git.Repository) {
	tc.repo = repo
}

func (tc *testCloner) Clone(context.Context) (*git.Repository, error) {
	return tc.repo, tc.err
}

func TestGitCloneTarget_Prepare(t *testing.T) {
	const (
		clonePath = "/workspace"
		repoURL   = "https://github.com/andream16/go-opentracing-example"
		reference = "main"
	)

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		fs          = memfs.New()
		conf        = &git.Conf{
			RepoURL:   repoURL,
			ClonePath: clonePath,
			Reference: reference,
		}
	)

	defer cancel()

	t.Run("it should clone successfully", func(t *testing.T) {
		cloner := &testCloner{}
		cloner.setRepo(&git.Repository{})

		target, err := git.NewTarget(
			conf,
			git.WithClock(clock),
			git.WithFS(fs),
			git.WithCloner(cloner),
		)
		require.NoError(t, err)
		require.NoError(t, target.Prepare(ctx))
	})

	t.Run("it should fail because cloning errored", func(t *testing.T) {
		cloner := &testCloner{}
		cloner.setErr(errors.New("no repo for you"))

		target, err := git.NewTarget(
			conf,
			git.WithClock(clock),
			git.WithFS(fs),
			git.WithCloner(cloner),
		)
		require.NoError(t, err)
		require.Error(t, target.Prepare(ctx))
	})
}
