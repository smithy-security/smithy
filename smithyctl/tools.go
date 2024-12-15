//go:build tools

package smithyctl

import (
	_ "github.com/abice/go-enum"
)

// ENUMs GEN
//go:generate go run github.com/abice/go-enum --file ./types/v1/parameter.go
