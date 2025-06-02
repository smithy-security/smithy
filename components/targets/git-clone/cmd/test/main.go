package main

import (
	"context"
	"log"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/targets/git-clone/internal/target"
	"github.com/smithy-security/smithy/components/targets/git-clone/pkg/git"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatalf("unexpected error: %v", err)
	}
}

func Main(ctx context.Context) error {
	conf, err := git.NewConf()
	if err != nil {
		return errors.Errorf("could not create new configuration: %w", err)
	}

	gitManager, err := git.NewManager(conf)
	if err != nil {
		return errors.Errorf("could not create new git manager: %w", err)
	}

	gitCloneTarget, err := target.NewTarget(conf, gitManager)
	if err != nil {
		return errors.Errorf("could not create git clone target: %w", err)
	}

	return gitCloneTarget.Prepare(ctx)
}
