//go:build tools

package tools

import (
	_ "go.uber.org/mock/mockgen"
)

// Mocks GEN
//go:generate go run go.uber.org/mock/mockgen -package engine_test -source internal/engine/engine.go -destination internal/engine/engine_mock_test.go ContainerExecutor
//go:generate go run go.uber.org/mock/mockgen -package workflow -source internal/command/workflow/parse.go -destination internal/command/workflow/parse_mock_test.go ComponentFetcher
//go:generate go run go.uber.org/mock/mockgen -package docker -source images/docker/builder.go -destination images/docker/docker_builder_mock.go
//go:generate go run go.uber.org/mock/mockgen -package images -source images/types.go -destination images/mocks.go
