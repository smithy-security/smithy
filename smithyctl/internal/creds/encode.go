package creds

import (
	"context"
	"encoding/base64"
	"encoding/json"

	dockerregistrytypes "github.com/docker/docker/api/types/registry"
	"github.com/go-errors/errors"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// GetAndEncode gets the expected credentials from the credentials store and
// encodes it.
func GetAndEncode(ctx context.Context, host string, credsStore credentials.Store) (string, error) {
	creds, err := credsStore.Get(ctx, host)
	if err != nil {
		return "", err
	}

	return Encode(creds)
}

// Encode encodes the OCI credentials into a base64 bearer token
func Encode(credential auth.Credential) (string, error) {
	if credential == auth.EmptyCredential {
		return "", nil
	}

	authConfigBytes, err := json.Marshal(dockerregistrytypes.AuthConfig{
		Username: credential.Username,
		Password: credential.Password,
	})
	if err != nil {
		return "", errors.Errorf("could not marshal registry authentication configuration: %w", err)
	}

	return base64.URLEncoding.EncodeToString(authConfigBytes), nil
}
