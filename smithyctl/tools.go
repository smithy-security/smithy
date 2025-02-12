//go:build tools

package tools

import (
	_ "go.uber.org/mock/mockgen"
)

// Mocks GEN
//go:generate go run go.uber.org/mock/mockgen -package engine_test -source internal/engine/engine.go -destination internal/engine/engine_mock_test.go ContainerExecutor
//go:generate go run go.uber.org/mock/mockgen -package workflow_test -source internal/command/workflow/parse.go -destination internal/command/workflow/parse_mock_test.go ComponentFetcher
