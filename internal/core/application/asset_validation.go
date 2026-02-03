package application

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/wire"
)

func (s *service) validateAssetTransaction(
	ctx context.Context, tx *wire.MsgTx, inputAssets map[int][]domain.Asset,
) errors.Error {
	assetTxos := make(map[int][]asset.AssetTxo)
	for inputIndex, assets := range inputAssets {
		assetTxs := make([]asset.AssetTxo, 0)
		for _, a := range assets {
			assetTxs = append(assetTxs, asset.AssetTxo{AssetID: a.AssetID, Amount: a.Amount})
		}
		assetTxos[inputIndex] = assetTxs
	}

	return asset.ValidateAssetTransaction(
		ctx, tx, assetTxos, ctrlAssetSource{s.repoManager.Assets()},
	)
}

type ctrlAssetSource struct {
	domain.AssetRepository
}

func (s ctrlAssetSource) GetControlAsset(ctx context.Context, assetID string) (string, error) {
	assetGroup, err := s.GetAssetGroupByID(ctx, assetID)
	if err != nil {
		return "", err
	}
	if assetGroup == nil {
		return "", fmt.Errorf("no control asset found")
	}
	return assetGroup.ControlAssetID, nil
}
