package uuid

import (
	"github.com/go-errors/errors"
	"github.com/google/uuid"
)

var Nil = UUID(uuid.Nil)

// UUID is an alias for a google uuid.
type UUID uuid.UUID

// New returns a new UUID.
func New() UUID {
	return UUID(uuid.New())
}

// Parse parses a string as UUID.
func Parse(s string) (UUID, error) {
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
