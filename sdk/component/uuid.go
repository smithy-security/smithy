package component

import (
	"github.com/go-errors/errors"
	"github.com/google/uuid"
)

// Nil is a UUID zero value.
var Nil = UUID(uuid.Nil)

// UUID is an alias for a google uuid.
type UUID uuid.UUID

// NewUUID returns a new UUID.
func NewUUID() UUID {
	return UUID(uuid.New())
}

// ParseUUID parses a string as UUID.
func ParseUUID(s string) (UUID, error) {
	if s == "" {
		return Nil, nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return Nil, errors.Errorf("invalid UUID string: %s", s)
	}
	return UUID(u), nil
}

// IsNil checks whether a uuid is nil or not.
func (u UUID) IsNil() bool {
	return u == Nil
}

// String returns a string containing the underlying uuid.
func (u UUID) String() string {
	return uuid.UUID(u).String()
}
