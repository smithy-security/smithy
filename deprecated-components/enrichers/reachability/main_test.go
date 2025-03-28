package main

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseTestdataPath = "./test/testdata"

	banditRawFileName      = "bandit.raw.pb"
	banditEnrichedFileName = "bandit.reachability.enriched.pb"
	safetyRawFileName      = "pip-safety.raw.pb"
	safetyEnrichedFileName = "pip-safety.reachability.enriched.pb"
)

var (
	resultsFilesPath  = path.Join(baseTestdataPath, "results")
	expectedFilesPath = path.Join(baseTestdataPath, "expectations")

	envVars = map[string]string{
		"READ_PATH":      baseTestdataPath,
		"WRITE_PATH":     resultsFilesPath,
		"ATOM_FILE_PATH": path.Join(baseTestdataPath, "reachables.json"),
	}
)

func TestEnricher(t *testing.T) {
	// Cleanup test bed.
	t.Cleanup(func() {
		for ev := range envVars {
			require.NoError(
				t,
				os.Unsetenv(ev),
			)
		}
		require.NoError(t, os.RemoveAll(resultsFilesPath))
	})

	// Setup test bed.
	for ev, val := range envVars {
		require.NoError(t, os.Setenv(ev, val))
	}

	t.Run("it correctly cancels and returns earlier", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		require.NoError(t, Main(ctx, cancel))
	})
	t.Run("it enriches bandit and safety reports as expected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		require.NoError(t, Main(ctx, cancel))

		// Does the results folder exist?
		require.DirExists(t, resultsFilesPath)
		for _, fp := range []string{
			banditRawFileName,
			banditEnrichedFileName,
			safetyRawFileName,
			safetyEnrichedFileName,
		} {
			// Do all expected result files exist?
			resFilePath := getResultPath(t, fp)
			require.FileExistsf(t, resFilePath, "result file %s doesn't exist in path", resFilePath)
			expFilePath := getExpectedPath(t, fp)
			require.FileExistsf(t, resFilePath, "expected file %s doesn't exist in path", expFilePath)

			resFile, err := os.ReadFile(resFilePath)
			require.NoErrorf(t, err, "could not open results file %s", resFilePath)

			expFile, err := os.ReadFile(expFilePath)
			require.NoErrorf(t, err, "could not open expectations file %s", expFilePath)

			assert.Equalf(
				t,
				string(resFile),
				string(expFile),
				"expected file %s doesn't match results file %s",
				expFilePath,
				resFilePath,
			)
		}
	})
}

func getResultPath(t *testing.T, fileName string) string {
	t.Helper()
	return path.Join(resultsFilesPath, fileName)
}

func getExpectedPath(t *testing.T, fileName string) string {
	t.Helper()
	return path.Join(expectedFilesPath, fileName)
}
