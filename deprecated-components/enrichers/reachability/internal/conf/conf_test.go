package conf_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/conf"
)

func TestNew(t *testing.T) {
	for _, tt := range []struct {
		testCase              string
		inProducerResultPath  string
		inEnrichedResultsPath string
		inATOMFilePath        string
		inEnricherAnnotation  string
		shouldErr             bool
		expectedConf          *conf.Conf
	}{
		{
			testCase:              "it should return an error because the producer result path is not set",
			inProducerResultPath:  "",
			inEnrichedResultsPath: "/enriched-results",
			inATOMFilePath:        "/atom-files",
			inEnricherAnnotation:  "SmithyIsCool",
			shouldErr:             true,
		},
		{
			testCase:              "it should return an error because the enriched result path is not set",
			inProducerResultPath:  "/producer-results",
			inEnrichedResultsPath: "",
			inATOMFilePath:        "/atom-files",
			inEnricherAnnotation:  "SmithyIsCool",
			shouldErr:             true,
		},
		{
			testCase:              "it should return an error because the atom file path is not set",
			inProducerResultPath:  "/producer-results",
			inEnrichedResultsPath: "/enriched-results",
			inATOMFilePath:        "",
			inEnricherAnnotation:  "SmithyIsCool",
			shouldErr:             true,
		},
		{
			testCase:              "it should return the expected configuration with a non empty enricher annotation as all the expected environment variables are set",
			inProducerResultPath:  "/producer-results",
			inEnrichedResultsPath: "/enriched-results",
			inATOMFilePath:        "/atom-files",
			inEnricherAnnotation:  "",
			shouldErr:             false,
			expectedConf: &conf.Conf{
				ProducerResultsPath: "/producer-results",
				EnrichedResultsPath: "/enriched-results",
				ATOMFilePath:        "/atom-files",
			},
		},
		{
			testCase:              "it should return the expected configuration as all the expected environment variables are set",
			inProducerResultPath:  "/producer-results",
			inEnrichedResultsPath: "/enriched-results",
			inATOMFilePath:        "/atom-files",
			inEnricherAnnotation:  "SmithyIsCool",
			shouldErr:             false,
			expectedConf: &conf.Conf{
				ProducerResultsPath: "/producer-results",
				EnrichedResultsPath: "/enriched-results",
				ATOMFilePath:        "/atom-files",
			},
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			require.NoError(
				t,
				os.Setenv(conf.ProducerResultsPathEnvVarName, tt.inProducerResultPath),
				os.Setenv(conf.EnrichedResultsPathEnvVarName, tt.inEnrichedResultsPath),
				os.Setenv(conf.AtomFilePathEnvVarName, tt.inATOMFilePath),
			)

			t.Cleanup(func() {
				require.NoError(
					t,
					os.Unsetenv(conf.ProducerResultsPathEnvVarName),
					os.Unsetenv(conf.EnrichedResultsPathEnvVarName),
					os.Unsetenv(conf.AtomFilePathEnvVarName),
				)
			})

			cfg, err := conf.New()
			switch {
			case tt.shouldErr && err == nil:
				t.Fatal("expected an error but didn't get one")
			case !tt.shouldErr && err != nil:
				t.Fatalf("unexpected error: %s", err)
			}

			assert.Equal(t, tt.expectedConf, cfg)
		})
	}
}
