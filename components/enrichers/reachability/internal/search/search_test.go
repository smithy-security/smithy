package search_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/search"
)

func TestNewSearcher(t *testing.T) {
	var (
		reachables     = make(atom.Reachables, 1, 1)
		reachablePurls = atom.ReachablePurls{
			"pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c": {},
		}
	)

	for _, tt := range []struct {
		testCase       string
		reachablePurls atom.ReachablePurls
		reachables     atom.Reachables
		expectsErr     bool
	}{
		{
			testCase:       "it returns an error because the supplied reachable purls are empty",
			reachablePurls: atom.ReachablePurls{},
			reachables:     reachables,
			expectsErr:     true,
		},
		{
			testCase:       "it returns an error because the supplied reachables are empty",
			reachablePurls: reachablePurls,
			reachables:     atom.Reachables{},
			expectsErr:     true,
		},
		{
			testCase:       "it returns a new searcher",
			reachablePurls: reachablePurls,
			reachables:     reachables,
			expectsErr:     false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			t.Parallel()

			rw, err := search.NewSearcher(tt.reachables, tt.reachablePurls)
			if tt.expectsErr {
				assert.Error(t, err)
				assert.Nil(t, rw)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, rw)
			}
		})
	}
}
