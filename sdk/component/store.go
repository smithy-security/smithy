package component

import (
	"context"

	"github.com/go-errors/errors"

	localstore "github.com/smithy-security/smithy/sdk/component/store/local"
	findingsclient "github.com/smithy-security/smithy/sdk/component/store/remote/findings-client"
	"github.com/smithy-security/smithy/sdk/component/store/remote/postgresql"
)

func newStore(ctx context.Context, storeType StoreType) (Storer, error) {
	switch storeType {
	case StoreTypeSqlite:
		return localstore.NewManager()
	case StoreTypePostgresql:
		return postgresql.NewManager(ctx)
	case StoreTypeFindingsClient:
		return findingsclient.New()
	}

	return nil, errors.Errorf("unsupported store type: %s", storeType)
}
