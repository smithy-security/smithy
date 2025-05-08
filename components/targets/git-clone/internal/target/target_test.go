package target_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/targets/git-clone/internal/target"
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
		repoURL   = "https://github.com/andream16/go-opentracing-example"
		reference = "main"
	)

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		clock       = clockwork.NewFakeClockAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC))
		conf        = &git.Conf{
			RepoURL:   repoURL,
			Reference: reference,
		}
	)

	defer cancel()

	t.Run("it should clone successfully", func(t *testing.T) {
		cloner := &testCloner{}
		cloner.setRepo(&git.Repository{})

		gt, err := target.NewTarget(
			conf,
			cloner,
			target.WithClock(clock),
		)
		require.NoError(t, err)
		require.NoError(t, gt.Prepare(ctx))
	})

	t.Run("it should fail because cloning errored", func(t *testing.T) {
		cloner := &testCloner{}
		cloner.setErr(errors.New("no repo for you"))

		gt, err := target.NewTarget(
			conf,
			cloner,
			target.WithClock(clock),
		)
		require.NoError(t, err)
		require.Error(t, gt.Prepare(ctx))
	})
}
