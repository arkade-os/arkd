package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type assetRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewAssetRepository(config ...interface{}) (domain.AssetRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open vtxo repository: invalid config")
	}

	return &assetRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *assetRepository) InsertTeleportAsset(ctx context.Context, teleport domain.TeleportAsset) error {
	return r.querier.CreateTeleportAsset(ctx, queries.CreateTeleportAssetParams{
		TeleportHash: teleport.Hash,
		AssetID:      teleport.AssetID,
		Amount:       int64(teleport.Amount),
		IsClaimed:    teleport.IsClaimed,
	})
}

func (r *assetRepository) GetTeleportAsset(ctx context.Context, teleportHash string) (*domain.TeleportAsset, error) {
	teleportDB, err := r.querier.GetTeleportAsset(ctx, teleportHash)
	if err != nil {
		return nil, err
	}
	return &domain.TeleportAsset{
		Hash:      teleportDB.TeleportHash,
		AssetID:   teleportDB.AssetID,
		Amount:    uint64(teleportDB.Amount),
		IsClaimed: teleportDB.IsClaimed,
	}, nil
}

func (r *assetRepository) UpdateTeleportAsset(ctx context.Context, teleportHash string, isClaimed bool) error {
	return r.querier.UpdateTeleportAsset(ctx, queries.UpdateTeleportAssetParams{
		TeleportHash: teleportHash,
		IsClaimed:    isClaimed,
	})
}

func (r *assetRepository) Close() {
	_ = r.db.Close()
}

func (r *assetRepository) ListMetadataByAssetID(ctx context.Context, assetID string) ([]domain.AssetMetadata, error) {
	res, err := r.querier.ListAssetMetadata(ctx, assetID)
	if err != nil {
		return nil, err
	}
	metadata := make([]domain.AssetMetadata, 0, len(res))
	for _, m := range res {
		metadata = append(metadata, domain.AssetMetadata{
			Key:   m.MetaKey,
			Value: m.MetaValue,
		})
	}
	return metadata, nil
}

func (r *assetRepository) InsertAssetAnchor(ctx context.Context, anchor domain.AssetAnchor) error {
	err := r.querier.CreateAssetAnchor(ctx, queries.CreateAssetAnchorParams{
		AnchorTxid: anchor.AnchorPoint.Txid,
		AnchorVout: int64(anchor.AnchorPoint.VOut),
		AssetID:    anchor.AssetID,
	})

	if err != nil {
		return err
	}

	for _, vtxo := range anchor.Vtxos {

		err := r.querier.AddAnchorVtxo(ctx, queries.AddAnchorVtxoParams{
			AnchorID: anchor.AnchorPoint.Txid,
			Vout:     int64(vtxo.Vout),
			Amount:   int64(vtxo.Amount),
		})

		if err != nil {
			return err
		}

	}

	return nil
}

func (r *assetRepository) GetAssetAnchorByTxId(ctx context.Context, txId string) (*domain.AssetAnchor, error) {
	anchor, err := r.querier.GetAssetAnchor(ctx, txId)
	if err != nil {
		return nil, err
	}

	vtxosDB, err := r.querier.ListAnchorVtxos(ctx, anchor.AnchorTxid)
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.AnchorVtxo, 0, len(vtxosDB))
	for _, vtxoDB := range vtxosDB {
		vtxos = append(vtxos, domain.AnchorVtxo{
			Vout:   uint32(vtxoDB.Vout),
			Amount: uint64(vtxoDB.Amount),
		})
	}

	return &domain.AssetAnchor{
		AnchorPoint: domain.Outpoint{
			Txid: anchor.AnchorTxid,
			VOut: uint32(anchor.AnchorVout),
		},
		AssetID: anchor.AssetID,
		Vtxos:   vtxos,
	}, nil
}

func (r *assetRepository) InsertAsset(ctx context.Context, asset domain.Asset) error {
	err := r.querier.CreateAsset(ctx, queries.CreateAssetParams{
		ID:        asset.ID,
		Quantity:  int64(asset.Quantity),
		Immutable: asset.Immutable,
	})

	if err != nil {
		return err
	}

	for _, md := range asset.Metadata {
		err := r.querier.UpsertAssetMetadata(ctx, queries.UpsertAssetMetadataParams{
			AssetID:   asset.ID,
			MetaKey:   md.Key,
			MetaValue: md.Value,
		})

		if err != nil {
			return err
		}
	}

	return nil

}

func (r *assetRepository) GetAssetByID(ctx context.Context, assetID string) (*domain.Asset, error) {
	assetDB, err := r.querier.GetAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}

	metadataDB, err := r.querier.ListAssetMetadata(ctx, assetID)
	if err != nil {
		return nil, err
	}

	metadata := make([]domain.AssetMetadata, 0, len(metadataDB))
	for _, mdDB := range metadataDB {
		metadata = append(metadata, domain.AssetMetadata{
			Key:   mdDB.MetaKey,
			Value: mdDB.MetaValue,
		})
	}

	return &domain.Asset{
		ID:        assetDB.ID,
		Quantity:  uint64(assetDB.Quantity),
		Immutable: assetDB.Immutable,
		Metadata:  metadata,
	}, nil
}

func (r *assetRepository) IncreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error {
	return r.querier.AddToAssetQuantity(ctx, queries.AddToAssetQuantityParams{
		ID:       assetID,
		Quantity: int64(amount),
	})
}

func (r *assetRepository) DecreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error {
	return r.querier.SubtractFromAssetQuantity(ctx, queries.SubtractFromAssetQuantityParams{
		ID:       assetID,
		Quantity: int64(amount),
	})
}

func (r *assetRepository) UpdateAssetMetadataList(ctx context.Context, assetId string, metadatalist []domain.AssetMetadata) error {
	for _, md := range metadatalist {
		err := r.querier.UpsertAssetMetadata(ctx, queries.UpsertAssetMetadataParams{
			AssetID:   assetId,
			MetaKey:   md.Key,
			MetaValue: md.Value,
		})

		if err != nil {
			return err
		}
	}

	return nil
}
