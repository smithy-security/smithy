package dbi

import "context"

type Entry struct {
	Value []byte
	Err   error
}

type RpmDBInterface interface {
	Read(ctx context.Context) <-chan Entry
	Close() error
}
