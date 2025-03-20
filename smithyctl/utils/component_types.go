package utils

import (
	"github.com/go-errors/errors"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

var (
	pluralToComponentType = map[string]v1.ComponentType{}
)

func init() {
	for _, ct := range v1.ComponentTypeValues() {
		pluralToComponentType[ct.String()+"s"] = ct
	}
}

// ComponentTypeFromPlural returns the ComponentType from the plural word
func ComponentTypeFromPlural(ct string) (v1.ComponentType, error) {
	if ct, exists := pluralToComponentType[ct]; exists {
		return ct, nil
	}

	return v1.ComponentTypeUnknown, errors.Errorf("no such component type: %s", ct)
}

// PluraliseComponentType returns the plural component type
func PluraliseComponentType(ct v1.ComponentType) string {
	return ct.String() + "s"
}
