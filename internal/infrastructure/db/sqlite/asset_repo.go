package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/shopspring/decimal"
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

func (r *assetRepository) AddAssets(
	ctx context.Context, assetsByTx map[string][]domain.Asset,
) (count int, err error) {
	if len(assetsByTx) == 0 {
		return -1, nil
	}

	assets := make([]domain.Asset, 0)
	seen := make(map[string]struct{})
	for _, assetList := range assetsByTx {
		for _, ast := range assetList {
			if _, exists := seen[ast.Id]; !exists {
				assets = append(assets, ast)
				seen[ast.Id] = struct{}{}
				continue
			}
			return -1, fmt.Errorf("duplicated asset %s", ast.Id)
		}
	}
	// Make sure all control assets are added first
	sort.SliceStable(assets, func(i, j int) bool {
		return assets[i].ControlAssetId == "" && assets[j].ControlAssetId != ""
	})

	txBody := func(querierWithTx *queries.Queries) error {
		for _, ast := range assets {
			found, err := querierWithTx.SelectAssetsByIds(ctx, []string{ast.Id})
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("failed to check existing asset: %w", err)
			}
			if len(found) > 0 {
				continue
			}

			var md, mdHash sql.NullString
			if len(ast.Metadata) > 0 {
				metadataHash, err := asset.GenerateMetadataListHash(ast.Metadata)
				if err != nil {
					return fmt.Errorf("failed to compute metadata hash: %w", err)
				}
				mdHash = sql.NullString{
					String: hex.EncodeToString(metadataHash),
					Valid:  true,
				}

				metadataList, err := asset.NewMetadataList(ast.Metadata)
				if err != nil {
					return fmt.Errorf("failed to create metadata list: %w", err)
				}
				md = sql.NullString{
					String: metadataList.String(),
					Valid:  true,
				}
			}
			if err := querierWithTx.InsertAsset(
				ctx, queries.InsertAssetParams{
					ID:           ast.Id,
					Metadata:     md,
					MetadataHash: mdHash,
					ControlAssetID: sql.NullString{
						String: ast.ControlAssetId,
						Valid:  len(ast.ControlAssetId) > 0,
					},
				},
			); err != nil {
				return err
			}
			count++
		}

		return nil
	}

	if err := execTx(ctx, r.db, txBody); err != nil {
		return -1, err
	}
	return count, nil
}

func (r *assetRepository) GetAssets(
	ctx context.Context, assetIds []string,
) ([]domain.Asset, error) {
	if len(assetIds) == 0 {
		return nil, nil
	}
	var assets []domain.Asset
	txBody := func(querierWithTx *queries.Queries) error {
		rows, err := querierWithTx.SelectAssetsByIds(ctx, assetIds)
		if err != nil {
			return err
		}
		assets = make([]domain.Asset, 0, len(rows))
		for _, row := range rows {
			// TODO: this is not efficient, but avoids overflows
			amounts, err := querierWithTx.SelectAssetAmounts(ctx, row.ID)
			if err != nil {
				return fmt.Errorf("failed to compute supply for asset %s: %w", row.ID, err)
			}
			supply := decimal.NewFromFloat(0)
			for _, amount := range amounts {
				// nolint
				dec, _ := decimal.NewFromString(amount)
				supply = supply.Add(dec)
			}

			ast := domain.Asset{
				Id:             row.ID,
				ControlAssetId: row.ControlAssetID.String,
				Supply:         *supply.BigInt(),
			}

			if row.Metadata.Valid {
				ast.Metadata, err = asset.NewMetadataListFromString(row.Metadata.String)
				if err != nil {
					// ignore error, metadata won't be set in the asset but do not fail the query
					continue
				}
			}
			assets = append(assets, ast)
		}
		return nil
	}
	if err := execTx(ctx, r.db, txBody); err != nil {
		return nil, err
	}
	return assets, nil
}

func (r *assetRepository) GetControlAsset(ctx context.Context, assetID string) (string, error) {
	controlID, err := r.querier.SelectControlAssetByID(ctx, assetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("no control asset found")
		}
		return "", err
	}
	if !controlID.Valid {
		return "", nil
	}
	return controlID.String, nil
}

func (r *assetRepository) AssetExists(ctx context.Context, assetID string) (bool, error) {
	_, err := r.querier.SelectAssetExists(ctx, assetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
