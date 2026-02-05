package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const assetStoreDir = "assets"

type assetRepository struct {
	store *badgerhold.Store
}

func NewAssetRepository(config ...interface{}) (domain.AssetRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, assetStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open asset store: %s", err)
	}

	return &assetRepository{store}, nil
}

func (r *assetRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *assetRepository) AddAssets(
	ctx context.Context, assetsByTx map[string][]domain.Asset,
) (int, error) {
	return r.addAssets(ctx, assetsByTx)
}

func (r *assetRepository) GetAssets(
	ctx context.Context,
	assetIDs []string,
) ([]domain.Asset, error) {
	return nil, nil
}

func (r *assetRepository) addAssets(
	ctx context.Context, assetsByTx map[string][]domain.Asset,
) (int, error) {
	count := 0
	for _, assets := range assetsByTx {
		for _, asset := range assets {
			var insertFn func() error
			if ctx.Value("tx") != nil {
				tx := ctx.Value("tx").(*badger.Txn)
				insertFn = func() error {
					return r.store.TxInsert(tx, asset.Id, asset)
				}
			} else {
				insertFn = func() error {
					return r.store.Insert(asset.Id, asset)
				}
			}
			if err := insertFn(); err != nil {
				if errors.Is(err, badgerhold.ErrKeyExists) {
					continue
				}
				if errors.Is(err, badger.ErrConflict) {
					attempts := 1
					for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
						time.Sleep(100 * time.Millisecond)
						err = insertFn()
						attempts++
					}
				}
				return -1, err
			}
			count++
		}
	}

	return count, nil
}
