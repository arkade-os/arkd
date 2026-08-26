package store

import (
	"fmt"

	filestore "github.com/arkade-os/arkd/pkg/client-wallet/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
)

type service struct {
	configStore types.Store
}

func NewStore(storeType, datadir string) (types.Store, error) {
	switch storeType {
	case types.InMemoryStore:
		return inmemorystore.NewStore()
	case types.FileStore:
		return filestore.NewStore(datadir)
	default:
		return nil, fmt.Errorf("unknown config store type")
	}
}
