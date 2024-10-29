package component

import "github.com/smithy-security/smithy/sdk/component/internal/storer/local"

type storeType string

const (
	storeTypeTest  storeType = "test"
	storeTypeLocal storeType = "local"
)

func isAllowedStoreType(st storeType) bool {
	return st == storeTypeLocal
}

// newStore - TODO - implement in another PR.
func newStorer(storeType storeType) (Storer, error) {
	localMgr, _ := local.NewStoreManager()
	return localMgr, nil
}
