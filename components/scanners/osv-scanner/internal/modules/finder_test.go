package modules

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/smithy-security/pkg/languages"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
)

func TestModuleListing(t *testing.T) {
	t.Run("all modules are found", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		t.Cleanup(cancel)

		finder, err := NewFinder(
			testCtx,
			config.Config{
				Root: ".",
			},
		)
		require.NoError(t, err)

		mixFiles, err := finder.Find(testCtx)
		require.NoError(t, err)
		require.Equal(t,
			map[string]languages.Language{
				"testdata/module1/mix.exs": languages.ELIXIR,
				"testdata/module2/mix.exs": languages.ELIXIR,
			},
			mixFiles,
		)
	})

	t.Run("unknown root path returns error", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		t.Cleanup(cancel)

		_, err := NewFinder(
			testCtx,
			config.Config{
				Root: "./bla",
			},
		)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("non-existent git diff causes no error", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		t.Cleanup(cancel)

		finder, err := NewFinder(
			testCtx,
			config.Config{
				Root:        ".",
				GitDiffPath: "./testdata/bla",
			},
		)
		require.NoError(t, err)

		mixFiles, err := finder.Find(testCtx)
		require.NoError(t, err)
		require.Equal(t,
			map[string]languages.Language{
				"testdata/module1/mix.exs": languages.ELIXIR,
				"testdata/module2/mix.exs": languages.ELIXIR,
			},
			mixFiles,
		)
	})

	t.Run("bad git diff causes error", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		t.Cleanup(cancel)

		_, err := NewFinder(
			testCtx,
			config.Config{
				Root:        "./testdata",
				GitDiffPath: "./testdata/module1",
			},
		)
		require.Error(t, err)
	})

	t.Run("finder returns only files that have been modified", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		t.Cleanup(cancel)

		finder, err := NewFinder(
			testCtx,
			config.Config{
				Root:        ".",
				GitDiffPath: "./testdata/test.git.diff",
			},
		)
		require.NoError(t, err)

		mixFiles, err := finder.Find(testCtx)
		require.NoError(t, err)
		require.Equal(t,
			map[string]languages.Language{
				"testdata/module1/mix.exs": languages.ELIXIR,
			},
			mixFiles,
		)
	})
}
