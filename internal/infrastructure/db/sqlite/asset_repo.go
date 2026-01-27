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

func (r *assetRepository) ListAssetAnchorsByAssetID(
	ctx context.Context,
	assetID string,
) ([]domain.AssetAnchor, error) {
	anchorsDB, err := r.querier.ListAssetAnchorsByAssetID(ctx, assetID)
	if err != nil {
		return nil, err
	}

	anchors := make([]domain.AssetAnchor, 0, len(anchorsDB))
	for _, anchorDB := range anchorsDB {
		anchor, err := r.GetAssetAnchorByTxId(ctx, anchorDB.AnchorTxid)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, *anchor)
	}

	return anchors, nil
}

func (r *assetRepository) GetAssetByOutpoint(
	ctx context.Context,
	outpoint domain.Outpoint,
) (*domain.NormalAsset, error) {
	{
		assetDB, err := r.querier.GetAsset(ctx, queries.GetAssetParams{
			AnchorID: outpoint.Txid,
			Vout:     int64(outpoint.VOut),
		})
		if err != nil {
			return nil, err
		}
		return &domain.NormalAsset{
			Outpoint: domain.Outpoint{
				Txid: assetDB.AnchorID,
				VOut: uint32(assetDB.Vout),
			},
			Amount:  uint64(assetDB.Amount),
			AssetID: assetDB.AssetID,
		}, nil
	}
}

func (r *assetRepository) InsertTeleportAsset(
	ctx context.Context,
	teleport domain.TeleportAsset,
) error {
	return r.querier.CreateTeleportAsset(ctx, queries.CreateTeleportAssetParams{
		Script:     teleport.Script,
		IntentID:   teleport.IntentID,
		GroupIndex: int64(teleport.OutputIndex),
		AssetID:    teleport.AssetID,
		Amount:     int64(teleport.Amount),
		IsClaimed:  teleport.IsClaimed,
	})
}

func (r *assetRepository) GetTeleportAsset(
	ctx context.Context,
	script string, intentID string, assetID string, outputIndex uint32,
) (*domain.TeleportAsset, error) {
	teleportDB, err := r.querier.GetTeleportAsset(ctx, queries.GetTeleportAssetParams{
		Script:     script,
		IntentID:   intentID,
		AssetID:    assetID,
		GroupIndex: int64(outputIndex),
	})
	if err != nil {
		return nil, err
	}
	return &domain.TeleportAsset{
		Script:      teleportDB.Script,
		AssetID:     teleportDB.AssetID,
		IntentID:    teleportDB.IntentID,
		OutputIndex: uint32(teleportDB.GroupIndex),
		Amount:      uint64(teleportDB.Amount),
		IsClaimed:   teleportDB.IsClaimed,
	}, nil
}

func (r *assetRepository) UpdateTeleportAsset(
	ctx context.Context,
	script string, intentID string, assetID string, outputIndex uint32, isClaimed bool,
) error {
	return r.querier.UpdateTeleportAsset(ctx, queries.UpdateTeleportAssetParams{
		IsClaimed:  isClaimed,
		Script:     script,
		IntentID:   intentID,
		AssetID:    assetID,
		GroupIndex: int64(outputIndex),
	})
}

func (r *assetRepository) Close() {
	_ = r.db.Close()
}

func (r *assetRepository) ListMetadataByAssetID(
	ctx context.Context,
	assetID string,
) ([]domain.AssetMetadata, error) {
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
		AnchorTxid: anchor.Txid,
		AnchorVout: int64(anchor.VOut),
	})

	if err != nil {
		return err
	}

	for _, asst := range anchor.Assets {
		err := r.querier.AddAsset(ctx, queries.AddAssetParams{
			AnchorID: anchor.Txid,
			AssetID:  asst.AssetID,
			Vout:     int64(asst.VOut),
			Amount:   int64(asst.Amount),
		})

		if err != nil {
			return err
		}

	}

	return nil
}

func (r *assetRepository) GetAssetAnchorByTxId(
	ctx context.Context,
	txId string,
) (*domain.AssetAnchor, error) {
	anchor, err := r.querier.GetAssetAnchor(ctx, txId)
	if err != nil {
		return nil, err
	}

	assetListResp, err := r.querier.ListAsset(ctx, anchor.AnchorTxid)
	if err != nil {
		return nil, err
	}

	assetList := make([]domain.NormalAsset, 0, len(assetListResp))
	for _, asst := range assetListResp {
		assetList = append(assetList, domain.NormalAsset{
			Outpoint: domain.Outpoint{
				Txid: asst.AnchorID,
				VOut: uint32(asst.Vout),
			},
			Amount:  uint64(asst.Amount),
			AssetID: asst.AssetID,
		})
	}

	return &domain.AssetAnchor{
		Outpoint: domain.Outpoint{
			Txid: anchor.AnchorTxid,
			VOut: uint32(anchor.AnchorVout),
		},
		Assets: assetList,
	}, nil
}

func (r *assetRepository) InsertAssetGroup(
	ctx context.Context,
	assetGroup domain.AssetGroup,
) error {
	controlId := sql.NullString{}
	if assetGroup.ControlAssetID != "" {
		controlId = sql.NullString{
			String: assetGroup.ControlAssetID,
			Valid:  true,
		}
	}

	err := r.querier.CreateAsset(ctx, queries.CreateAssetParams{
		ID:        assetGroup.ID,
		Quantity:  int64(assetGroup.Quantity),
		Immutable: assetGroup.Immutable,
		ControlID: controlId,
	})

	if err != nil {
		return err
	}

	for _, md := range assetGroup.Metadata {
		err := r.querier.UpsertAssetMetadata(ctx, queries.UpsertAssetMetadataParams{
			AssetID:   assetGroup.ID,
			MetaKey:   md.Key,
			MetaValue: md.Value,
		})

		if err != nil {
			return err
		}
	}

	return nil

}

func (r *assetRepository) GetAssetGroupByID(
	ctx context.Context,
	assetID string,
) (*domain.AssetGroup, error) {
	assetDB, err := r.querier.GetAssetGroup(ctx, assetID)
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

	return &domain.AssetGroup{
		ID:             assetDB.ID,
		Quantity:       uint64(assetDB.Quantity),
		Metadata:       metadata,
		ControlAssetID: assetDB.ControlID.String,
		Immutable:      assetDB.Immutable,
	}, nil
}

func (r *assetRepository) IncreaseAssetGroupQuantity(
	ctx context.Context,
	assetID string,
	amount uint64,
) error {
	return r.querier.AddToAssetQuantity(ctx, queries.AddToAssetQuantityParams{
		ID:       assetID,
		Quantity: int64(amount),
	})
}

func (r *assetRepository) DecreaseAssetGroupQuantity(
	ctx context.Context,
	assetID string,
	amount uint64,
) error {
	return r.querier.SubtractFromAssetQuantity(ctx, queries.SubtractFromAssetQuantityParams{
		ID:       assetID,
		Quantity: int64(amount),
	})
}

func (r *assetRepository) UpdateAssetMetadataList(
	ctx context.Context,
	assetId string,
	metadatalist []domain.AssetMetadata,
) error {
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
