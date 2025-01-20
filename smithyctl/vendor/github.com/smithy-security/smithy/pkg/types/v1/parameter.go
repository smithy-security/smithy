package v1

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrMismatchedExpectedType is returned when the type field of a parameter
	// is not the same as the actual type of the value of a parameter.
	ErrMismatchedExpectedType = errors.New("stated parameter type different than actual value type")
	// ErrUnknownParameterType is returned when the type of field parameter
	// is not one of the expected values.
	ErrUnknownParameterType = errors.New("unknown parameter type")
)

type (
	// ParameterType represents the type of parameter that can be parsed by the
	// system.
	// ENUM(string, const:string, list:string)
	ParameterType string

	// Parameter is a struct whose value must be of the type as it's defined in the
	// Type field. Due to the fact that this value is expected to be communicated
	// to external clients via JSON, which doesn't support rich types, we need to
	// communicate the expected value type via an enum string. Given the Golang
	// type system, there is no way to enforce the type restrictions via an
	// interface, so do all the type checks when marshaling/unmarshalling the JSON
	// bytes, since this type will constantly be subject to such transformations.
	Parameter struct {
		// Name is the name of the parameter.
		Name string `json:"name" yaml:"name"`
		// Type is the parameter type.
		Type ParameterType `json:"type" yaml:"type"`
		// Value is the JSON encoded/decoded value of the parameter which is decoded based its Type.
		Value any `json:"value" yaml:"value"`
	}
)

// UnmarshalJSON unmarshal JSON bytes into a Parameter object.
func (p *Parameter) UnmarshalJSON(b []byte) error {
	partialParameter := &struct {
		Name string
		Type ParameterType
	}{}

	var err error
	if err = json.Unmarshal(b, partialParameter); err != nil {
		return err
	}

	p.Name = partialParameter.Name
	p.Type = partialParameter.Type

	switch partialParameter.Type {
	case ParameterTypeString, ParameterTypeConststring:
		parameterValueStrPtr := &struct{ Value *string }{}
		if err = json.Unmarshal(b, parameterValueStrPtr); err == nil {
			if parameterValueStrPtr.Value != nil {
				p.Value = *parameterValueStrPtr.Value
			}
			break
		}
		parameterValueStr := &struct{ Value string }{}
		err = json.Unmarshal(b, parameterValueStr)
		p.Value = parameterValueStr.Value
	case ParameterTypeListstring:
		parameterValue := &struct{ Value []string }{}
		err = json.Unmarshal(b, parameterValue)
		p.Value = parameterValue.Value
	default:
		err = ErrUnknownParameterType
	}
	if err != nil {
		return fmt.Errorf("parameter.Name: %s, parameter.Type: %s: %w", partialParameter.Name, partialParameter.Type, err)
	}

	return nil
}

// MarshalJSON marshals the Parameter into JSON bytes.
func (p *Parameter) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	b, err := json.Marshal(struct {
		Name  string
		Type  ParameterType
		Value any
	}{
		Name:  p.Name,
		Type:  p.Type,
		Value: p.Value,
	})
	if err != nil {
		return nil, fmt.Errorf("could not json marshal value: %w", err)
	}

	return b, nil
}

// Validate checks all the fields of the parameter to make sure that the type
// specified matches the actual type of the value
func (p *Parameter) Validate() error {
	_, err := ParseParameterType(string(p.Type))
	if err != nil {
		return fmt.Errorf("could not parse parameter '%s' with type: '%s': %w", p.Name, p.Type, err)
	}

	if p.Value == nil {
		return nil
	}

	b, err := json.Marshal(p.Value)
	if err != nil {
		return fmt.Errorf("could not marshal value for parameter '%s': %w", p.Name, err)
	}

	var correctType bool

	switch p.Type {
	case ParameterTypeString, ParameterTypeConststring:
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("could not unmarshal value for parameter '%s': %w", p.Name, err)
		}
		correctType = true
	case ParameterTypeListstring:
		var ss []string
		if err := json.Unmarshal(b, &ss); err != nil {
			return fmt.Errorf("could not unmarshal value for parameter '%s': %w", p.Name, err)
		}

		correctType = true
	default:
		err = ErrUnknownParameterType
	}

	if !correctType {
		err = ErrMismatchedExpectedType
	}

	if err != nil {
		return fmt.Errorf(
			"invalid parameter '%s' with type '%s' and value '%v': %w",
			p.Name,
			p.Type,
			p.Value,
			err,
		)
	}

	return nil
}
