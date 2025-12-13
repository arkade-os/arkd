package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path/filepath"

	filestore "github.com/arkade-os/arkd/pkg/client-lib/store/file"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/store/inmemory"
	kvstore "github.com/arkade-os/arkd/pkg/client-lib/store/kv"
	sqlstore "github.com/arkade-os/arkd/pkg/client-lib/store/sql"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed sql/migration/*
var migrations embed.FS

const (
	sqliteDbFile = "sqlite.db"
)

type service struct {
	configStore types.ConfigStore
	utxoStore   types.UtxoStore
	vtxoStore   types.VtxoStore
	txStore     types.TransactionStore
}

type Config struct {
	ConfigStoreType  string
	AppDataStoreType string

	BaseDir string
}

func NewStore(storeConfig Config) (types.Store, error) {
	var (
		configStore types.ConfigStore
		utxoStore   types.UtxoStore
		vtxoStore   types.VtxoStore
		txStore     types.TransactionStore
		err         error

		dir = storeConfig.BaseDir
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

	if len(storeConfig.AppDataStoreType) > 0 {
		switch storeConfig.AppDataStoreType {
		case types.KVStore:
			utxoStore, err = kvstore.NewUtxoStore(dir, nil)
			if err != nil {
				return nil, err
			}
			vtxoStore, err = kvstore.NewVtxoStore(dir, nil)
			if err != nil {
				return nil, err
			}
			txStore, err = kvstore.NewTransactionStore(dir, nil)
		case types.SQLStore:
			dbFile := filepath.Join(dir, sqliteDbFile)
			db, err := sqlstore.OpenDb(dbFile)
			if err != nil {
				return nil, err
			}
			driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
			if err != nil {
				return nil, fmt.Errorf("failed to init driver: %s", err)
			}

			source, err := iofs.New(migrations, "sql/migration")
			if err != nil {
				return nil, fmt.Errorf("failed to embed migrations: %s", err)
			}

			m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
			if err != nil {
				return nil, fmt.Errorf("failed to create migration instance: %s", err)
			}

			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return nil, fmt.Errorf("failed to run migrations: %s", err)
			}
			utxoStore = sqlstore.NewUtxoStore(db)
			vtxoStore = sqlstore.NewVtxoStore(db)
			txStore = sqlstore.NewTransactionStore(db)
		default:
			err = fmt.Errorf("unknown appdata store type")
		}
		if err != nil {
			return nil, err
		}
	}

	return &service{configStore, utxoStore, vtxoStore, txStore}, nil
}

func (s *service) ConfigStore() types.ConfigStore {
	return s.configStore
}

func (s *service) UtxoStore() types.UtxoStore {
	return s.utxoStore
}

func (s *service) VtxoStore() types.VtxoStore {
	return s.vtxoStore
}

func (s *service) TransactionStore() types.TransactionStore {
	return s.txStore
}

func (s *service) Clean(ctx context.Context) {
	//nolint:all
	s.configStore.CleanData(ctx)
	if s.txStore != nil {
		//nolint:all
		s.txStore.Clean(ctx)
	}
	if s.vtxoStore != nil {
		//nolint:all
		s.vtxoStore.Clean(ctx)
	}
}

func (s *service) Close() {
	s.configStore.Close()
	s.vtxoStore.Close()
	s.txStore.Close()
}
