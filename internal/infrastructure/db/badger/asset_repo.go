package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const assetStoreDir = "assets"

type assetRepository struct {
	store *badgerhold.Store
}

type asset struct {
	ID        string `badgerhold:"key"`
	Quantity  uint64
	Immutable bool
}

type assetMetadata struct {
	Key       string `badgerhold:"key"`
	AssetID   string `badgerhold:"index"`
	MetaKey   string
	MetaValue string
}

type assetAnchor struct {
	AnchorTxid string `badgerhold:"key"`
	AnchorVout uint32
	AssetID    string
}

type anchorVtxo struct {
	AnchorID string `badgerhold:"index"`
	Vout     uint32
	Amount   uint64
}

type teleportAsset struct {
	Hash      string `badgerhold:"key"`
	AssetID   string `badgerhold:"index"`
	Amount    uint64
	IsClaimed bool
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

func (r *assetRepository) ListMetadataByAssetID(
	ctx context.Context, assetID string,
) ([]domain.AssetMetadata, error) {
	query := badgerhold.Where("AssetID").Eq(assetID)

	var metadata []assetMetadata
	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxFind(tx, &metadata, query)
	} else {
		err = r.store.Find(&metadata, query)
	}
	if err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return []domain.AssetMetadata{}, nil
		}
		return nil, err
	}

	meta := make([]domain.AssetMetadata, 0, len(metadata))
	for _, m := range metadata {
		meta = append(meta, domain.AssetMetadata{
			Key:   m.MetaKey,
			Value: m.MetaValue,
		})
	}

	return meta, nil
}

func (r *assetRepository) InsertAssetAnchor(
	ctx context.Context, anchor domain.AssetAnchor,
) error {
	anchorRecord := assetAnchor{
		AnchorTxid: anchor.AnchorPoint.Txid,
		AnchorVout: anchor.AnchorPoint.VOut,
		AssetID:    anchor.AssetID,
	}

	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		if err := r.store.TxInsert(tx, anchorRecord.AnchorTxid, anchorRecord); err != nil {
			return err
		}

		for _, vtxo := range anchor.Vtxos {
			record := anchorVtxo{
				AnchorID: anchorRecord.AnchorTxid,
				Vout:     vtxo.Vout,
				Amount:   vtxo.Amount,
			}

			if err := r.store.TxUpsert(tx, anchorVtxoKey(anchorRecord.AnchorTxid, vtxo.Vout), record); err != nil {
				return err
			}
		}

		return nil
	})
}

func (r *assetRepository) InsertTeleportAsset(ctx context.Context, teleport domain.TeleportAsset) error {
	record := teleportAsset{
		Hash:      teleport.Hash,
		AssetID:   teleport.AssetID,
		Amount:    teleport.Amount,
		IsClaimed: teleport.IsClaimed,
	}

	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		return r.store.TxInsert(tx, record.Hash, record)
	})
}

func (r *assetRepository) UpdateTeleportAsset(ctx context.Context, hash string, isClaimed bool) error {
	var teleport teleportAsset

	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxGet(tx, hash, &teleport)
	} else {
		err = r.store.Get(hash, &teleport)
	}
	if err != nil {
		return err
	}

	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		record := teleportAsset{
			Hash:      hash,
			AssetID:   teleport.AssetID,
			Amount:    teleport.Amount,
			IsClaimed: isClaimed,
		}

		return r.store.TxUpsert(tx, hash, record)
	})
}

func (r *assetRepository) GetTeleportAsset(
	ctx context.Context, hash string,
) (*domain.TeleportAsset, error) {
	var teleport teleportAsset

	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxGet(tx, hash, &teleport)
	} else {
		err = r.store.Get(hash, &teleport)
	}
	if err != nil {
		return nil, err
	}

	return &domain.TeleportAsset{
		Hash:      teleport.Hash,
		AssetID:   teleport.AssetID,
		Amount:    teleport.Amount,
		IsClaimed: teleport.IsClaimed,
	}, nil
}

func (r *assetRepository) GetAssetAnchorByTxId(
	ctx context.Context, txId string,
) (*domain.AssetAnchor, error) {
	var anchor assetAnchor

	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxGet(tx, txId, &anchor)
	} else {
		err = r.store.Get(txId, &anchor)
	}
	if err != nil {
		return nil, err
	}

	vtxos, err := r.listAnchorVtxos(ctx, txId)
	if err != nil {
		return nil, err
	}

	anchorVtxos := make([]domain.AnchorVtxo, 0, len(vtxos))
	for _, v := range vtxos {
		anchorVtxos = append(anchorVtxos, domain.AnchorVtxo{
			Vout:   v.Vout,
			Amount: v.Amount,
		})
	}

	return &domain.AssetAnchor{
		AnchorPoint: domain.Outpoint{
			Txid: anchor.AnchorTxid,
			VOut: anchor.AnchorVout,
		},
		AssetID: anchor.AssetID,
		Vtxos:   anchorVtxos,
	}, nil
}

func (r *assetRepository) InsertAsset(ctx context.Context, a domain.Asset) error {
	record := asset{
		ID:        a.ID,
		Quantity:  a.Quantity,
		Immutable: a.Immutable,
	}

	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		if err := r.store.TxInsert(tx, record.ID, record); err != nil {
			return err
		}

		for _, md := range a.Metadata {
			meta := assetMetadata{
				Key:       assetMetadataKey(a.ID, md.Key),
				AssetID:   a.ID,
				MetaKey:   md.Key,
				MetaValue: md.Value,
			}

			if err := r.store.TxUpsert(tx, meta.Key, meta); err != nil {
				return err
			}
		}

		return nil
	})
}

func (r *assetRepository) GetAssetByID(
	ctx context.Context, assetID string,
) (*domain.Asset, error) {
	dbAsset, err := r.getAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}

	metadata, err := r.ListMetadataByAssetID(ctx, assetID)
	if err != nil {
		return nil, err
	}

	return &domain.Asset{
		ID:        dbAsset.ID,
		Quantity:  dbAsset.Quantity,
		Immutable: dbAsset.Immutable,
		Metadata:  metadata,
	}, nil
}

func (r *assetRepository) IncreaseAssetQuantity(
	ctx context.Context, assetID string, amount uint64,
) error {
	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		dbAsset, err := r.getAssetWithTx(tx, assetID)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				return nil
			}
			return err
		}

		dbAsset.Quantity += amount

		return r.store.TxUpsert(tx, assetID, dbAsset)
	})
}

func (r *assetRepository) DecreaseAssetQuantity(
	ctx context.Context, assetID string, amount uint64,
) error {
	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		dbAsset, err := r.getAssetWithTx(tx, assetID)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				return nil
			}
			return err
		}

		if dbAsset.Quantity < amount {
			return fmt.Errorf("insufficient quantity for asset %s", assetID)
		}

		dbAsset.Quantity -= amount

		return r.store.TxUpsert(tx, assetID, dbAsset)
	})
}

func (r *assetRepository) UpdateAssetMetadataList(
	ctx context.Context, assetId string, metadatalist []domain.AssetMetadata,
) error {
	return r.withRetryableWrite(ctx, func(tx *badger.Txn) error {
		_, err := r.getAssetWithTx(tx, assetId)
		if err != nil {
			return err
		}

		for _, md := range metadatalist {
			meta := assetMetadata{
				Key:       assetMetadataKey(assetId, md.Key),
				AssetID:   assetId,
				MetaKey:   md.Key,
				MetaValue: md.Value,
			}

			if err := r.store.TxUpsert(tx, meta.Key, meta); err != nil {
				return err
			}
		}

		return nil
	})
}

func (r *assetRepository) listAnchorVtxos(
	ctx context.Context, anchorID string,
) ([]anchorVtxo, error) {
	var vtxos []anchorVtxo
	query := badgerhold.Where("AnchorID").Eq(anchorID)

	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxFind(tx, &vtxos, query)
	} else {
		err = r.store.Find(&vtxos, query)
	}
	if err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return []anchorVtxo{}, nil
		}
		return nil, err
	}

	sort.Slice(vtxos, func(i, j int) bool {
		return vtxos[i].Vout < vtxos[j].Vout
	})

	return vtxos, nil
}

func (r *assetRepository) getAsset(
	ctx context.Context, assetID string,
) (*asset, error) {
	var record asset
	var err error
	if tx := getTxFromContext(ctx); tx != nil {
		err = r.store.TxGet(tx, assetID, &record)
	} else {
		err = r.store.Get(assetID, &record)
	}
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (r *assetRepository) getAssetWithTx(
	tx *badger.Txn, assetID string,
) (*asset, error) {
	var record asset
	if err := r.store.TxGet(tx, assetID, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *assetRepository) withRetryableWrite(
	ctx context.Context, fn func(tx *badger.Txn) error,
) error {
	if tx := getTxFromContext(ctx); tx != nil {
		return fn(tx)
	}

	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		err = func() error {
			tx := r.store.Badger().NewTransaction(true)
			defer tx.Discard()

			if err := fn(tx); err != nil {
				return err
			}

			return tx.Commit()
		}()
		if err == nil {
			return nil
		}

		if errors.Is(err, badger.ErrConflict) {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return err
	}

	return err
}

func getTxFromContext(ctx context.Context) *badger.Txn {
	tx, ok := ctx.Value("tx").(*badger.Txn)
	if !ok {
		return nil
	}

	return tx
}

func anchorVtxoKey(anchorID string, vout uint32) string {
	return fmt.Sprintf("%s:%d", anchorID, vout)
}

func assetMetadataKey(assetID, metaKey string) string {
	return fmt.Sprintf("%s:%s", assetID, metaKey)
}
