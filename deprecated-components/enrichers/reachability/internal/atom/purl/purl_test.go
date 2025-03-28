package purl_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/atom/purl"
)

func TestParser_ParsePurl(t *testing.T) {
	p, err := purl.NewParser()
	require.NoError(t, err)

	for _, tt := range []struct {
		inputPurl       string
		expectedMatches []string
		expectedError   bool
	}{
		{
			inputPurl:     "hey",
			expectedError: true,
		},
		{
			inputPurl:     "pkg:bitbucket/birkenfeld/pygments-main",
			expectedError: true,
		},
		{
			inputPurl:     "pkg:bitbucket/birkenfeld/pygments-main@v1",
			expectedError: true,
		},
		{
			inputPurl:     "pkg:bitbucket/birkenfeld/pygments-main@v1.1",
			expectedError: true,
		},
		{
			inputPurl:     "pkg:bitbucket/birkenfeld/pygments-main@244",
			expectedError: true,
		},
		{
			inputPurl: "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			expectedMatches: []string{
				"birkenfeld/pygments-main:244fd47e07d1014f0aed9c",
				"pygments-main:244fd47e07d1014f0aed9c",
				"birkenfeld/pygments-main:244fd47",
				"pygments-main:244fd47",
			},
		},
		{
			inputPurl: "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			expectedMatches: []string{
				"debian/curl:7.50.3-1",
				"curl:7.50.3-1",
			},
		},
		{
			inputPurl: "pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c",
			expectedMatches: []string{
				"package-url/purl-spec:244fd47e07d1004f0aed9c",
				"purl-spec:244fd47e07d1004f0aed9c",
				"package-url/purl-spec:244fd47",
				"purl-spec:244fd47",
			},
		},
		{
			inputPurl: "pkg:github/package-url/purl-spec@v1.2.3-beta",
			expectedMatches: []string{
				"package-url/purl-spec:v1.2.3-beta",
				"purl-spec:v1.2.3-beta",
			},
		},
	} {
		t.Run(
			fmt.Sprintf("parsing with input %s should succeed: %v", tt.inputPurl, !tt.expectedError),
			func(t *testing.T) {
				pp, err := p.ParsePurl(tt.inputPurl)
				if tt.expectedError {
					require.Error(t, err)
					assert.Nil(t, pp)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.expectedMatches, pp)
			})
	}
}
