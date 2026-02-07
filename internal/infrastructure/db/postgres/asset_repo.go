package pgdb

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

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
		mdHashByAssetId := make(map[string]string)
		for _, ast := range assets {
			found, err := querierWithTx.SelectAssetsByIds(ctx, []string{ast.Id})
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("failed to check existing asset: %w", err)
			}
			if len(found) > 0 {
				continue
			}

			var mdHash []byte
			var md pqtype.NullRawMessage
			if len(ast.Metadata) > 0 {
				mdHash, err = asset.GenerateMetadataListHash(ast.Metadata)
				if err != nil {
					return fmt.Errorf("failed to compute metadata hash: %w", err)
				}
				// store metadata as JSON {key [string]: value [string]}
				buf, _ := json.Marshal(toMetadataDTO(ast.Metadata))
				md = pqtype.NullRawMessage{
					RawMessage: buf,
					Valid:      true,
				}
				mdHashByAssetId[ast.Id] = hex.EncodeToString(mdHash)
			}
			if err := querierWithTx.InsertAsset(
				ctx, queries.InsertAssetParams{
					ID:       ast.Id,
					Metadata: md,
					MetadataHash: sql.NullString{
						String: hex.EncodeToString(mdHash),
						Valid:  len(mdHash) > 0,
					},
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
			supplyStr, err := querierWithTx.SelectAssetSupply(ctx, row.ID)
			if err != nil {
				return fmt.Errorf("failed to compute supply for asset %s: %w", row.ID, err)
			}
			supply := new(big.Int)
			if _, ok := supply.SetString(supplyStr, 10); !ok {
				return fmt.Errorf("invalid supply value: %s", supplyStr)
			}
			var metadata []asset.Metadata
			if row.Metadata.Valid {
				md := make([]metadataDTO, 0)
				if err := json.Unmarshal(row.Metadata.RawMessage, &md); err != nil {
					return fmt.Errorf("failed to decode asset metadata: %w", err)
				}
				for _, dto := range md {
					metadata = append(metadata, asset.Metadata{
						Key:   []byte(dto.Key),
						Value: []byte(dto.Value),
					})
				}
			}
			assets = append(assets, domain.Asset{
				Id:             row.ID,
				Metadata:       metadata,
				ControlAssetId: row.ControlAssetID.String,
				Supply:         *supply,
			})
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

type metadataDTO struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func toMetadataDTO(mdList []asset.Metadata) []metadataDTO {
	metadataDTOs := make([]metadataDTO, 0, len(mdList))
	for _, md := range mdList {
		metadataDTOs = append(metadataDTOs, metadataDTO{
			Key:   string(md.Key),
			Value: string(md.Value),
		})
	}
	return metadataDTOs
}
