package purl

import (
	"fmt"
	"path"
	"regexp"

	"github.com/package-url/packageurl-go"
)

// Parser allows to extract information from purls - https://github.com/package-url/purl-spec.
type Parser struct {
	semverPattern    *regexp.Regexp
	shaCommitPattern *regexp.Regexp
}

// NewParser returns a new parser.
func NewParser() (*Parser, error) {
	// Matches SEMVER versions: v1.1.0 / v1.1.0-beta.
	semverPattern, err := regexp.Compile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z\-\.]+)?(\+[0-9A-Za-z\-\.]+)?$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile purl semver regex: %w", err)
	}
	// Matches SHA commit hashes from 7 (short) to 40 characters.
	shaCommitPattern, err := regexp.Compile(`^[a-fA-F0-9]{7,40}$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile sha commit pattern regex: %w", err)
	}

	return &Parser{
		semverPattern:    semverPattern,
		shaCommitPattern: shaCommitPattern,
	}, nil
}

// ParsePurl extracts namespace:name:version sub-parts from purls, based on the type of versioning used (SHA, SEMVER).
func (p *Parser) ParsePurl(purl string) ([]string, error) {
	pp, err := packageurl.FromString(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	if pp.Version == "" {
		return nil, fmt.Errorf("failed to parse purl: empty version")
	}

	var (
		namespace    = pp.Namespace
		name         = pp.Name
		version      = pp.Version
		shortVersion string
		purlParts    = []string{
			path.Join(namespace, name) + ":" + version,
			name + ":" + version,
		}
	)

	switch {
	case p.semverPattern.MatchString(version):
		return purlParts, nil
	case p.shaCommitPattern.MatchString(version):
		// Short commit SHA.
		shortVersion = version[:7]
		purlParts = append(purlParts, []string{
			path.Join(namespace, name) + ":" + shortVersion,
			name + ":" + shortVersion,
		}...)
	default:
		return nil, fmt.Errorf("failed to parse purl, invalid version: %s", version)
	}

	return purlParts, nil
}
