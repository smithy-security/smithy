package component

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/go-errors/errors"
	"gopkg.in/yaml.v3"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

type specParser struct{}

// NewSpecParser returns a new component spec parser.
func NewSpecParser() *specParser {
	return &specParser{}
}

// Parse reads, parses and validates components' configuration.
func (sp *specParser) Parse(path string) (*v1.Component, error) {
	const (
		defaultSmithyComponentFileNameYaml = "component.yaml"
		defaultSmithyComponentFileNameYml  = "component.yml"
	)

	if !strings.HasSuffix(path, defaultSmithyComponentFileNameYaml) && !strings.HasSuffix(path, defaultSmithyComponentFileNameYml) {
		return nil, errors.Errorf(
			"invalid file path %s, has to point to a component file",
			path,
		)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("%s does not exist", path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var component v1.Component
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&component); err != nil {
		return nil, fmt.Errorf("failed decode file '%s': %w", path, err)
	}

	if err := component.Validate(); err != nil {
		return nil, errors.Errorf("invalid component spec: %w", err)
	}

	return &component, nil
}
