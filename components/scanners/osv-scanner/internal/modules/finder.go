package modules

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/languages"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
)

// Map of common dependency file names to their corresponding language.
// The language names are aligned with go-enry conventions.
var dependencyFiles = map[string]languages.Language{
	"go.mod":            languages.GOLANG,
	"go.sum":            languages.GOLANG,
	"package.json":      languages.JAVASCRIPT,
	"package-lock.json": languages.JAVASCRIPT,
	"mix.exs":           languages.ELIXIR,
	"mix.lock":          languages.ELIXIR,
	// "rebar.config":      languages.ERLANG,
	// "requirements.txt":  languages.PYTHON,
	// "Pipfile":           languages.PYTHON,
	// "pyproject.toml":    languages.PYTHON,
	// "Cargo.toml":        languages.RUST,
	// "Cargo.lock":        languages.RUST,
}

// Finder analyses a directory and discovers all the Elixir mix.exs files in it
type Finder struct {
	cfg config.Config
}

// NewFinder returns a configured finder that can be used to analyse a
// directory
func NewFinder(ctx context.Context, cfg config.Config) (Finder, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	if cfg.GitDiffPath != "" {
		fInfo, err := os.Stat(cfg.GitDiffPath)
		if err != nil {
			logger.Info(
				"no git diff available, will proceed without filtering",
				slog.String("err", err.Error()),
			)
			cfg.GitDiffPath = ""
		} else if fInfo.IsDir() {
			return Finder{}, errors.Errorf("%s: git diff path points to a directory", cfg.GitDiffPath)
		}
	}

	if cfg.Root == "" {
		return Finder{}, errors.Errorf("%s: no path to root directory provided", cfg.Root)
	}

	fInfo, err := os.Stat(cfg.Root)
	if err != nil {
		return Finder{}, errors.Errorf(
			"%s: could not access repository root path: %w",
			cfg.Root, err,
		)
	}

	if !fInfo.IsDir() {
		return Finder{}, errors.Errorf("%s: path to repository root is not a directory", cfg.Root)
	}

	return Finder{
		cfg: cfg,
	}, nil
}

// Find will return a list of paths to Elixir mix.exs files.
func (f Finder) Find(ctx context.Context) (map[string]languages.Language, error) {
	logger := componentlogger.LoggerFromContext(ctx)
	lockFilePaths := map[string]languages.Language{}
	modules := map[string]languages.Language{}

	gitDiffFiles, err := f.getGitDiff(ctx)
	if err != nil {
		return nil, errors.Errorf("could not parse git diff file: %w", err)
	}

	if len(gitDiffFiles) > 0 {
		logger.Info("checking git diff for modified dependency files")
		for _, file := range gitDiffFiles {
			fileName := filepath.Base(file.NewName)
			if lang, ok := dependencyFiles[fileName]; ok {
				lockFilePath := filepath.Join(f.cfg.Root, file.NewName)
				modulePath := filepath.Dir(lockFilePath)

				if discoveredLang, ok := modules[modulePath]; ok && discoveredLang == lang {
					// we have already found that path X is a path to a module
					// of the some language, we don't need to re-add it to our
					// list
					continue
				}

				logger.Info(
					"discovered module from git diff",
					slog.String("path", lockFilePath),
					slog.String("language", lang.String()),
				)

				lockFilePaths[lockFilePath] = lang
				modules[modulePath] = lang
			}
		}

		return lockFilePaths, nil
	}

	logger.Info("looking for language modules...")
	err = filepath.WalkDir(
		f.cfg.Root,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Info(
					"could not access path",
					slog.String("path", path),
					slog.String("err", err.Error()),
				)
				return nil
			}

			if !d.IsDir() {
				return nil
			}

			for lockfile, language := range dependencyFiles {
				lockFilePath := filepath.Join(path, lockfile)
				_, statErr := os.Stat(lockFilePath)
				if statErr != nil {
					continue
				}

				modules[lockFilePath] = language
				logger.Info(
					"discovered module",
					slog.String("language", language.String()),
					slog.String("path", path),
				)
				// we found our file, don't explore further down the subtree
				return filepath.SkipDir

			}

			return nil
		},
	)

	return modules, err
}

func (f *Finder) getGitDiff(ctx context.Context) ([]*gitdiff.File, error) {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(
			slog.String("git_diff_path", f.cfg.GitDiffPath),
		)

	if f.cfg.GitDiffPath == "" {
		logger.Debug("no git diff found, skipping")
		return nil, nil
	}

	fd, err := os.OpenFile(f.cfg.GitDiffPath, os.O_RDONLY, 0666)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("no git diff file found, skipping")
			return nil, nil
		}
		return nil, errors.Errorf("%s: could not open git diff file: %w", f.cfg.GitDiffPath, err)
	}

	diffFiles, _, err := gitdiff.Parse(fd)
	if err != nil {
		return nil, errors.Errorf("could not parse raw.diff file: %w", err)
	}

	return diffFiles, fd.Close()
}
