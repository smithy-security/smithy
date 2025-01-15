//go:build tools

package smithy

import (
	_ "github.com/abice/go-enum"
)

// ENUMs GEN
//go:generate go run github.com/abice/go-enum --file ./pkg/types/v1/parameter.go
