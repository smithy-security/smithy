//go:build tools

package tools

import (
	_ "go.uber.org/mock/mockgen"
)

//go:generate go run go.uber.org/mock/mockgen -package mocks -source component/component.go -destination component/internal/mocks/component_mock.go
