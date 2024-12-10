package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component"

	"github.com/smithy-security/smithy/new-components/targets/git-clone/pkg/git"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	conf, err := git.NewConf(nil)
	if err != nil {
		return errors.Errorf("could not create new configuration: %w", err)
	}

	gitCloneTarget, err := git.NewTarget(conf)
	if err != nil {
		return errors.Errorf("could not create git clone target: %w", err)
	}

	opts := append(make([]component.RunnerOption, 0), component.RunnerWithComponentName("git-clone"))

	if err := component.RunTarget(
		ctx,
		gitCloneTarget,
		opts...,
	); err != nil {
		return errors.Errorf("could not run target: %w", err)
	}

	return nil
}
