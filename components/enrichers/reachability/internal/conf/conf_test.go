package conf_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/conf"
)

func TestNew(t *testing.T) {
	for _, tt := range []struct {
		testCase              string
		inProducerResultPath  string
		inEnrichedResultsPath string
		inATOMFileGlob        string
		inEnricherAnnotation  string
		shouldErr             bool
		expectedConf          *conf.Conf
	}{

		{
			testCase:       "it should return the expected configuration with a non empty enricher annotation as all the expected environment variables are set",
			inATOMFileGlob: "/atom-files/*.json",
			shouldErr:      false,
			expectedConf: &conf.Conf{
				ATOMFileGlob: "/atom-files/*.json",
			},
		},
		{
			testCase:       "it should return and error when atom file path not set",
			inATOMFileGlob: "",
			shouldErr:      true,
			expectedConf:   nil,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			require.NoError(
				t,
				os.Setenv(conf.AtomFileGlobEnvVarName, tt.inATOMFileGlob),
			)

			t.Cleanup(func() {
				require.NoError(
					t,
					os.Unsetenv(conf.AtomFileGlobEnvVarName),
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
