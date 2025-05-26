package component

import (
	"context"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/store/local/sqlite"
	findingsclient "github.com/smithy-security/smithy/sdk/component/store/remote/findings-client"
	"github.com/smithy-security/smithy/sdk/component/store/remote/postgresql"
)

func newStore(ctx context.Context, storeType StoreType) (Storer, error) {
	switch storeType {
	case StoreTypeSqlite:
		return sqlite.NewManager(ctx)
	case StoreTypePostgresql:
		return postgresql.NewManager(ctx)
	case StoreTypeFindingsClient:
		return findingsclient.New()
	}

	return nil, errors.Errorf("unsupported store type: %s", storeType)
}
