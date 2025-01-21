package enricher_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom/purl"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/conf"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/enricher"
)

func TestNewEnricher(t *testing.T) {
	cfg := &conf.Conf{}

	purlParser, err := purl.NewParser()
	require.NoError(t, err)

	r, err := atom.NewReader("/some/path", purlParser)
	require.NoError(t, err)

	for _, tt := range []struct {
		testCase   string
		cfg        *conf.Conf
		atomReader *atom.Reader
		expectsErr bool
	}{
		{
			testCase:   "it returns an error because the supplied configuration is nil",
			cfg:        nil,
			atomReader: r,
			expectsErr: true,
		},
		{
			testCase:   "it returns an error because the supplied atom reader is nil",
			cfg:        cfg,
			atomReader: nil,
			expectsErr: true,
		},
		{
			testCase:   "it returns a new enricher",
			cfg:        cfg,
			atomReader: r,
			expectsErr: false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			t.Parallel()
			enr, err := enricher.NewEnricher(tt.cfg, tt.atomReader)
			if tt.expectsErr {
				assert.Error(t, err)
				assert.Nil(t, enr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, enr)
			}
		})
	}
}
