package main

import (
	"context"
)

type gitCloneTarget struct {
}

func (g gitCloneTarget) Prepare(ctx context.Context) error {
	return nil
}
