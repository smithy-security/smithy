package docker

import "github.com/go-errors/errors"

var (
	// ErrNoDockerClient is returned when the docker constructors in this
	// package take a nil Docker client instance
	ErrNoDockerClient = errors.New("no docker client provided")
)
