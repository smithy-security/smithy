package enricher

import (
	"errors"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/conf"
)

type (
	enricher struct {
		cfg        *conf.Conf
		atomReader *atom.Reader
	}
)

// NewEnricher returns a new reachability enricher.
func NewEnricher(
	cfg *conf.Conf,
	atomReader *atom.Reader,
) (*enricher, error) {
	switch {
	case cfg == nil:
		return nil, errors.New("invalid nil configuration provided")
	case atomReader == nil:
		return nil, errors.New("invalid nil atom reader provided")
	}

	return &enricher{
		cfg:        cfg,
		atomReader: atomReader,
	}, nil
}
