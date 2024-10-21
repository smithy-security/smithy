package search

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom"
)

// Searcher is responsible for finding reachable purls in the supplied reachability report.
type Searcher struct {
	reachablePurls  atom.ReachablePurls
	reachables      atom.Reachables
	matcherFileLine *regexp.Regexp
}

// NewSearcher returns a new searcher.
func NewSearcher(reachables atom.Reachables, reachablePurls atom.ReachablePurls) (*Searcher, error) {
	switch {
	case len(reachables) == 0:
		return nil, errors.New("invalid empty reachables")
	case len(reachablePurls) == 0:
		return nil, errors.New("invalid empty reachable purls")
	}

	matcherFileLine, err := regexp.Compile(`(?P<file>[^/]+):(?P<line>[\d-]+)`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile matcher file line regex: %w", err)
	}

	return &Searcher{
		reachables:      reachables,
		reachablePurls:  reachablePurls,
		matcherFileLine: matcherFileLine,
	}, nil
}

// Search finds reachable purls in the supplied reachability report.
func (s *Searcher) Search(search string) (bool, error) {
	if search == "" {
		return false, errors.New("invalid empty search")
	}

	// If the search term is for a purl and there's a match, return early.
	if s.reachablePurls.IsPurlReachable(search) {
		return true, nil
	}

	// Otherwise check for a file match
	if match := s.matcherFileLine.FindStringSubmatch(search); len(match) > 0 {
		var (
			file        = match[1]
			fileContent = match[2]
		)

		lineStart, lineEnd, err := s.searchLineRange(fileContent)
		if err != nil {
			return false, fmt.Errorf("failed to parse line range: %w", err)
		}

		return s.searchReachableFlows(file, lineStart, lineEnd), nil
	}

	return false, nil
}

// searchLineRange searches in the lines of a file for a match.
func (s *Searcher) searchLineRange(search string) (int, int, error) {
	if parts := strings.Split(search, "-"); len(parts) >= 2 {
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid integer for first entry %v: %w", parts[0], err)
		}

		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid integer for second entry %v: %w", parts[1], err)
		}

		return start, end, nil
	}

	num, err := strconv.Atoi(search)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid integer for fallback value %v: %w", search, err)
	}

	return num, num, nil
}

// searchReachableFlows searches flows based on file name, and line numbers.
func (s *Searcher) searchReachableFlows(fileName string, startLine, endLine int) bool {
	for _, reachable := range s.reachables {
		for _, flow := range reachable.Flows {
			// In this case the match is not in this flow.
			if flow.LineNumber == 0 || flow.LineNumber < startLine || flow.LineNumber > endLine {
				continue
			}
			if strings.HasSuffix(flow.ParentFileName, fileName) {
				return true
			}
		}
	}
	return false
}
