package pgdb

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/sqlc-dev/pqtype"
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
		return nil, fmt.Errorf("cannot open asset repository: invalid config")
	}

	return &assetRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *assetRepository) Close() {
	_ = r.db.Close()
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
		anchor, err := r.GetAssetAnchorByTxId(ctx, anchorDB.FkIntentTxid.String)
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
	asset, err := r.querier.GetAssetProjectionsByOutpoint(ctx, queries.GetAssetProjectionsByOutpointParams{
		Txid: sql.NullString{String: outpoint.Txid, Valid: true},
		Vout: sql.NullInt64{Int64: int64(outpoint.VOut), Valid: true},
	})
	if err != nil {
		return nil, err
	}

	return &domain.NormalAsset{
		Outpoint: domain.Outpoint{
			Txid: asset.FkVtxoTxid.String,
			VOut: uint32(asset.FkVtxoVout.Int64),
		},
		Amount:  uint64(asset.Amount),
		AssetID: asset.FkAssetID,
	}, nil
}

func (r *assetRepository) ListMetadataByAssetID(
	ctx context.Context,
	assetID string,
) ([]domain.AssetMetadata, error) {
	res, err := r.querier.GetAssetMetadataByAssetID(ctx, assetID)
	if err != nil {
		return nil, err
	}
	metadata := make([]domain.AssetMetadata, 0)
	if res.Valid {
		var mdMap map[string]string
		err = json.Unmarshal(res.RawMessage, &mdMap)
		if err != nil {
			return nil, err
		}
		for k, v := range mdMap {
			metadata = append(metadata, domain.AssetMetadata{
				Key:   k,
				Value: v,
			})
		}
	}
	return metadata, nil
}

func (r *assetRepository) InsertAssetAnchor(ctx context.Context, anchor domain.AssetAnchor) error {
	for _, asst := range anchor.Assets {
		// derive txid and index from AssetID
		assetId, err := asset.NewAssetIdFromString(asst.AssetID)
		genesisTxid := assetId.Txid.String()
		genesisIndex := strconv.FormatUint(uint64(assetId.Index), 10)

		err = r.querier.AddAssetProjection(ctx, queries.AddAssetProjectionParams{
			FkIntentTxid: sql.NullString{String: anchor.Txid, Valid: true},
			FkIntentVout: sql.NullInt64{Int64: int64(anchor.VOut), Valid: true},
			FkAssetID:    genesisTxid,
			FkAssetIndex: genesisIndex,
			FkVtxoTxid:   sql.NullString{String: asst.Txid, Valid: true},
			FkVtxoVout:   sql.NullInt64{Int64: int64(asst.VOut), Valid: true},
			Amount:       int64(asst.Amount),
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

	// the txId is a fk_intent_txid from projection table
	assets, err := r.querier.GetAssetProjectionsByTxId(ctx, sql.NullString{String: txId, Valid: true})
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("asset anchor not found for txid: %s", txId)
	}
	anchorVout := assets[0].FkIntentVout.Int64

	assetList := make([]domain.NormalAsset, 0, len(assets))
	for _, asst := range assets {
		assetList = append(assetList, domain.NormalAsset{
			Outpoint: domain.Outpoint{
				Txid: asst.FkVtxoTxid.String,
				VOut: uint32(asst.FkVtxoVout.Int64),
			},
			Amount:  uint64(asst.Amount),
			AssetID: asst.FkAssetID,
		})
	}

	return &domain.AssetAnchor{
		Outpoint: domain.Outpoint{
			Txid: txId,
			VOut: uint32(anchorVout),
		},
		Assets: assetList,
	}, nil
}

func (r *assetRepository) InsertAssetGroup(
	ctx context.Context,
	assetGroup domain.AssetGroup,
) error {
	controlID := sql.NullString{}
	controlAssetGroupIndex := sql.NullInt64{}
	if assetGroup.ControlAssetID != "" {
		controlID = sql.NullString{
			String: assetGroup.ControlAssetID,
			Valid:  true,
		}
		// derive control asset asset index from control asset id
		controlAssetId, err := asset.NewAssetIdFromString(assetGroup.ControlAssetID)
		if err != nil {
			return err
		}
		controlAssetGroupIndex = sql.NullInt64{Int64: int64(controlAssetId.Index), Valid: true}
	}

	var metadata pqtype.NullRawMessage
	if len(assetGroup.Metadata) == 0 {
		metadata.Valid = false
	} else {
		jsonBytes, err := json.Marshal(assetGroup.Metadata)
		if err != nil {
			panic(err)
		}
		metadata = pqtype.NullRawMessage{
			RawMessage: jsonBytes,
			Valid:      true,
		}
	}

	// convert domain.AssetMetadata to pkg/ark-lib/asset/Metadata
	arLibMetadata := make([]asset.Metadata, 0, len(assetGroup.Metadata))
	for _, md := range assetGroup.Metadata {
		arLibMetadata = append(arLibMetadata, asset.Metadata{
			Key:   []byte(md.Key),
			Value: []byte(md.Value),
		})
	}
	metadataHashBytes, err := asset.GenerateMetadataListHash(arLibMetadata)
	if err != nil {
		return err
	}

	metadataHash := sql.NullString{String: hex.EncodeToString(metadataHashBytes), Valid: true}

	genesisTxid := ""
	genesisGroupIndex := int64(0)
	if assetGroup.ID != "" {
		// derive txid and index from AssetID
		producedAssetId, err := asset.NewAssetIdFromString(assetGroup.ID)
		if err != nil {
			return err
		}
		genesisTxid = producedAssetId.Txid.String()
		genesisGroupIndex = int64(producedAssetId.Index)
	}

	err = r.querier.CreateAsset(ctx, queries.CreateAssetParams{
		GenesisTxid:            genesisTxid,
		GenesisGroupIndex:      genesisGroupIndex,
		IsImmutable:            assetGroup.Immutable,
		Metadata:               metadata,
		MetadataHash:           metadataHash,
		ControlAssetID:         controlID,
		ControlAssetGroupIndex: controlAssetGroupIndex,
	})

	if err != nil {
		return err
	}

	// derive txid from assetGroup.ID
	// what do we do if its empty? the FkAssetID/FkAssetIndex are required fields
	assetId, err := asset.NewAssetIdFromString(assetGroup.ID)

	err = r.querier.UpsertAssetMetadataUpdate(ctx, queries.UpsertAssetMetadataUpdateParams{
		// should this be the controlAssetId or genesis txid (as specified in the schema)?
		FkAssetID:    assetId.Txid.String(),
		FkAssetIndex: strconv.FormatUint(uint64(assetId.Index), 10),
		// this fxn called for asset issuance only so no offchain items here?
		FkIntentTxid: sql.NullString{String: "", Valid: false},
		FkIntentVout: sql.NullInt64{Int64: 0, Valid: false},
		FkTxid:       sql.NullString{String: "", Valid: false},
		MetadataHash: metadataHash.String,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *assetRepository) GetAssetGroupByID(
	ctx context.Context,
	assetID string,
) (*domain.AssetGroup, error) {
	// derive txid
	assetId, err := asset.NewAssetIdFromString(assetID)
	genesisTxid := assetId.Txid.String()

	assetDB, err := r.querier.GetAssetEntryByTxid(ctx, genesisTxid)
	if err != nil {
		return nil, err
	}

	amounts, err := r.querier.GetAssetProjectionAmountByAssetId(ctx, assetID)
	if err != nil {
		return nil, err
	}

	// sum amounts
	quantity := int64(0)
	for _, amt := range amounts {
		quantity += amt
	}

	metadata, err := r.ListMetadataByAssetID(ctx, assetID)
	if err != nil {
		return nil, err
	}

	return &domain.AssetGroup{
		ID: assetID,
		// are we still keeping track of quantity?
		Quantity:       uint64(quantity),
		Immutable:      assetDB.IsImmutable,
		Metadata:       metadata,
		ControlAssetID: assetDB.ControlAssetID.String,
	}, nil
}

func (r *assetRepository) AddAssets(
	ctx context.Context,
	assets []domain.Asset,
) (int, error) {
	if len(assets) == 0 {
		return 0, nil
	}

	addedCount := 0
	for _, ast := range assets {
		controlID := sql.NullString{}
		controlAssetGroupIndex := sql.NullInt64{}
		if ast.ControlAssetId != "" {
			controlID = sql.NullString{
				String: ast.ControlAssetId,
				Valid:  true,
			}
			// derive control asset asset index from control asset id
			controlAssetId, err := asset.NewAssetIdFromString(ast.ControlAssetId)
			if err != nil {
				return addedCount, err
			}
			controlAssetGroupIndex = sql.NullInt64{Int64: int64(controlAssetId.Index), Valid: true}
		}

		var metadata pqtype.NullRawMessage
		if len(ast.Metadata) == 0 {
			metadata.Valid = false
		} else {
			jsonBytes, err := json.Marshal(ast.Metadata)
			if err != nil {
				panic(err)
			}
			metadata = pqtype.NullRawMessage{
				RawMessage: jsonBytes,
				Valid:      true,
			}
		}

		// convert asset.Metadata to to pkg/ark-lib/asset/Metadata
		arLibMetadata := make([]asset.Metadata, 0, len(ast.Metadata))
		for k, v := range ast.Metadata {
			arLibMetadata = append(arLibMetadata, asset.Metadata{
				Key:   []byte(k),
				Value: []byte(v),
			})
		}

		metadataHashBytes, err := asset.GenerateMetadataListHash(arLibMetadata)
		if err != nil {
			return addedCount, err
		}

		genesisTxid := ""
		genesisGroupIndex := int64(0)
		if ast.AssetID != "" {
			// derive txid and index from AssetID
			producedAssetId, err := asset.NewAssetIdFromString(ast.AssetID)
			if err != nil {
				return addedCount, err
			}
			genesisTxid = producedAssetId.Txid.String()
			genesisGroupIndex = int64(producedAssetId.Index)
		}

		// should we be using the upsert query?
		// should the control fields not be as i have them set here?
		params := queries.CreateAssetParams{
			// can we just use ast.AssetID here?
			GenesisTxid:       genesisTxid,
			GenesisGroupIndex: genesisGroupIndex,
			IsImmutable:       ast.Immutable,
			Metadata:          metadata,
			MetadataHash:      sql.NullString{String: hex.EncodeToString(metadataHashBytes), Valid: true},
			// can we just use ast.ControlAssetId here? possible the control asset not provided and we have to set Valid: false
			ControlAssetID:         controlID,
			ControlAssetGroupIndex: controlAssetGroupIndex,
		}
		err = r.querier.CreateAsset(ctx, params)
		if err != nil {
			return addedCount, err
		}
		addedCount++
	}

	return addedCount, nil
}

func (r *assetRepository) GetAssets(
	ctx context.Context,
	assetIDs []string,
) ([]domain.Asset, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	assets := make([]domain.Asset, 0, len(assetIDs))
	for _, assetID := range assetIDs {
		ast, err := r.querier.GetAssetByAssetID(ctx, sql.NullString{String: assetID, Valid: true})
		if err != nil {
			return nil, err
		}
		producedAssetId, err := asset.NewAssetId(ast.GenesisTxid, uint16(ast.GenesisGroupIndex))
		if err != nil {
			return nil, err
		}
		formedAssetId := producedAssetId.String()
		metadata := make(map[string]string)
		if ast.Metadata.Valid {
			err = json.Unmarshal(ast.Metadata.RawMessage, &metadata)
			if err != nil {
				return nil, err
			}
		}
		domainAsset := domain.Asset{
			AssetID:        formedAssetId,
			Metadata:       metadata,
			ControlAssetId: ast.ControlAssetID.String,
			Immutable:      ast.IsImmutable,
		}
		assets = append(assets, domainAsset)
	}

	return assets, nil
}
