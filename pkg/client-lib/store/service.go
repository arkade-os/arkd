package store

import (
	"context"
	"fmt"

	filestore "github.com/arkade-os/arkd/pkg/client-lib/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type service struct {
	configStore types.ConfigStore
}

type Config struct {
	ConfigStoreType string
	BaseDir         string
}

func NewStore(storeConfig Config) (types.Store, error) {
	var (
		configStore types.ConfigStore
		err         error
		dir         = storeConfig.BaseDir
	)

	switch storeConfig.ConfigStoreType {
	case types.InMemoryStore:
		configStore, err = inmemorystore.NewConfigStore()
	case types.FileStore:
		configStore, err = filestore.NewConfigStore(dir)
	default:
		err = fmt.Errorf("unknown config store type")
	}
	if err != nil {
		return nil, err
	}

	return &service{configStore}, nil
}

func (s *service) ConfigStore() types.ConfigStore {
	return s.configStore
}

func (s *service) Clean(ctx context.Context) {
	//nolint:all
	s.configStore.CleanData(ctx)
}

func (s *service) Close() {
	s.configStore.Close()
}
