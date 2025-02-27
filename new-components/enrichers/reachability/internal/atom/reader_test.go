package atom_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/new-components/enrichers/reachability/internal/atom/purl"
)

func TestNewReader(t *testing.T) {
	purlParser, err := purl.NewParser()
	require.NoError(t, err)

	for _, tt := range []struct {
		testCase     string
		atomFilePath string
		purlParser   *purl.Parser
		expectsErr   bool
	}{
		{
			testCase:     "it returns an error because the supplied atom file is empty",
			atomFilePath: "",
			purlParser:   purlParser,
			expectsErr:   true,
		},
		{
			testCase:     "it returns an error because the supplied purl parser is nil",
			atomFilePath: "/some/path",
			purlParser:   nil,
			expectsErr:   true,
		},
		{
			testCase:     "it returns a reader",
			atomFilePath: "/some/path",
			purlParser:   purlParser,
			expectsErr:   false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			t.Parallel()

			r, err := atom.NewReader(tt.atomFilePath, tt.purlParser)
			if tt.expectsErr {
				assert.Error(t, err)
				assert.Nil(t, r)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, r)
			}
		})
	}
}
