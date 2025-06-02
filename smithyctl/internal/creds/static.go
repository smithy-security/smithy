package creds

import (
	"context"
	"net/url"

	"github.com/go-errors/errors"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// StaticStore is a struct implementing the
// oras.land/oras-go/v2/registry/remote/credentials.Store interface which is
// used in various places to fetch the authentication credentials for a
// registry
type StaticStore struct {
	host, username, password string
}

// NewStaticStore returns a new instance of the Store interface that will
// return only the credentials provided
func NewStaticStore(host, username, password string) (StaticStore, error) {
	if host == "" {
		return StaticStore{}, errors.Errorf("invalid empty host %s", host)
	}

	_, err := url.Parse(host)
	switch {
	case err != nil:
		return StaticStore{}, errors.Errorf("could not parse host %s: %w", host, err)
	case username == "":
		return StaticStore{}, errors.New("username provided is empty")
	case password == "":
		return StaticStore{}, errors.New("password provided is empty")
	}

	return StaticStore{
		host:     host,
		username: username,
		password: password,
	}, nil
}

// Get returns the credentials related to the serverAddress only if the server
// address is exactly the same as the one the store was initialised with
func (s StaticStore) Get(_ context.Context, serverAddress string) (auth.Credential, error) {
	if serverAddress != s.host {
		return auth.Credential{}, errors.Errorf("no credentials for %s", serverAddress)
	}

	return auth.Credential{
		Username: s.username,
		Password: s.password,
	}, nil
}

// Put should not be used for this store
func (s StaticStore) Put(_ context.Context, serverAddress string, cred auth.Credential) error {
	return nil
}

// Delete should not be used for this store
func (s StaticStore) Delete(_ context.Context, serverAddress string) error {
	return nil
}
