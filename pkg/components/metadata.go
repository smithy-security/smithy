package components

import (
	"slices"

	"github.com/go-errors/errors"
)

// LabelKey is the key of the label where the value must be a string of the
// ComponentType enum
const LabelKey string = "v1.smithy.smithy-security.com/component"

// ComponentType represents all the types of components that Smithy supports
// ENUM(unknown, base, source, producer, producer-aggregator, enricher, enricher-aggregator, consumer)
type ComponentType string

// LabelValueOneOf checks if the labels map has the expected key set and if
// that key has any one of the expected values
func LabelValueOneOf(labels map[string]string, componentTypes ...ComponentType) (bool, error) {
	labelValue, hasComponentType := labels[LabelKey]
	if !hasComponentType {
		return false, errors.Errorf("no %s key in labels", LabelKey)
	}

	labelCt, err := ParseComponentType(labelValue)
	if err != nil {
		return false, err
	}

	for _, componentType := range componentTypes {
		if labelCt == componentType {
			return true, nil
		}
	}

	return false, nil
}

// GetPrevious returns previous component type
// e.g. If we want the previous component type of Producer, we get Source
func GetPrevious(componentType ComponentType) ComponentType {
	allComponentTypes := ComponentTypeValues()
	currentTypeIndex := slices.Index(allComponentTypes, componentType)

	previousComponentType := Base
	if currentTypeIndex >= 1 {
		previousComponentType = allComponentTypes[currentTypeIndex-1]
	}

	return previousComponentType
}

// ADifferenceFromB returns the difference in position between ComponentType A and ComponentType B
// e.g. Enricher is 2 steps further along the pipeline than Producer
func ADifferenceFromB(componentTypeA ComponentType, componentTypeB ComponentType) int {
	allComponentTypes := ComponentTypeValues()
	return slices.Index(allComponentTypes, componentTypeA) - slices.Index(allComponentTypes, componentTypeB)
}

// AGreaterThanB returns whether ComponentType A is further along the pipeline than ComponentType B
// e.g. Enricher is further along the pipeline than Producer
func AGreaterThanB(componentTypeA ComponentType, componentTypeB ComponentType) bool {
	return ADifferenceFromB(componentTypeA, componentTypeB) > 0
}
