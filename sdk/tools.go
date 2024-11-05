//go:build tools

package sdk

import (
	_ "github.com/abice/go-enum"
	_ "go.uber.org/mock/mockgen"
)

// ENUMs GEN
//go:generate go run github.com/abice/go-enum --file ./component/enum.go ./...
//go:generate go run github.com/abice/go-enum --file ./component/internal/storer/local/sqlite/enum.go ./...

// Mocks GEN
//go:generate go run go.uber.org/mock/mockgen -package mocks -source component/component.go -destination component/internal/mocks/component_mock.go
