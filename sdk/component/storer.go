package component

import (
	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/internal/storer/local/sqlite"
)

type storeType string

const storeTypeLocal storeType = "local"

func isAllowedStoreType(st storeType) bool {
	return st == storeTypeLocal
}

func newStorer(conf runnerConfigStorer) (Storer, error) {
	if conf.storeType == storeTypeLocal {
		localMgr, err := sqlite.NewManager(conf.dbDSN)
		if err != nil {
			return nil, errors.Errorf("unable to initialize local sqlite manager: %w", err)
		}
		return localMgr, nil
	}
	return nil, errors.Errorf("curently unsupported store type: %s", conf.storeType)
}
