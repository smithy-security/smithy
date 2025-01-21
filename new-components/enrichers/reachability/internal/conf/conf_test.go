package conf_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/conf"
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
			testCase:       "it should return the expected configuration with a non empty enricher annotation as all the expected environment variables are set",
			inATOMFilePath: "/atom-files",
			shouldErr:      false,
			expectedConf: &conf.Conf{
				ATOMFilePath: "/atom-files",
			},
		},
		{
			testCase:       "it should return and error when atom file path not set",
			inATOMFilePath: "",
			shouldErr:      true,
			expectedConf:   nil,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			require.NoError(
				t,
				os.Setenv(conf.AtomFilePathEnvVarName, tt.inATOMFilePath),
			)

			t.Cleanup(func() {
				require.NoError(
					t,
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
