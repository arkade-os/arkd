package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const assetStoreDir = "assets"

type assetRepository struct {
	store    *badgerhold.Store
	vtxoRepo domain.VtxoRepository
}

func NewAssetRepository(config ...interface{}) (domain.AssetRepository, error) {
	if len(config) != 2 && len(config) != 3 {
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
	var vtxoRepo domain.VtxoRepository
	if len(config) == 3 && config[2] != nil {
		vtxoRepo, ok = config[2].(domain.VtxoRepository)
		if !ok {
			return nil, fmt.Errorf("invalid vtxo repository")
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

	return &assetRepository{store: store, vtxoRepo: vtxoRepo}, nil
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
	if len(assetIDs) == 0 {
		return nil, nil
	}
	var result []domain.Asset
	for _, id := range assetIDs {
		var a domain.Asset
		err := r.store.Get(id, &a)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if r.vtxoRepo != nil {
			if supply := r.computeSupply(ctx, id); supply != nil {
				a.Supply.Set(supply)
			}
		}
		result = append(result, a)
	}
	return result, nil
}

func (r *assetRepository) GetControlAsset(ctx context.Context, assetID string) (string, error) {
	var a domain.Asset
	err := r.store.Get(assetID, &a)
	if err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return "", fmt.Errorf("no control asset found")
		}
		return "", err
	}
	return a.ControlAssetId, nil
}

func (r *assetRepository) AssetExists(ctx context.Context, assetID string) (bool, error) {
	var a domain.Asset
	err := r.store.Get(assetID, &a)
	if err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// computeSupply returns the sum of unspent vtxo amounts for the asset (big.Int to avoid overflow).
func (r *assetRepository) computeSupply(ctx context.Context, assetID string) *big.Int {
	vtxos, err := r.vtxoRepo.GetAllVtxos(ctx)
	if err != nil {
		return nil
	}
	sum := new(big.Int)
	for _, v := range vtxos {
		if v.Spent {
			continue
		}
		for _, ad := range v.Assets {
			if ad.AssetId == assetID {
				sum.Add(sum, new(big.Int).SetUint64(ad.Amount))
			}
		}
	}
	return sum
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
