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
	ctx context.Context, tx *wire.MsgTx, inputAssets map[int][]domain.AssetDenomination,
) errors.Error {
	assetsPrevout := make(map[int][]asset.Asset)
	for inputIndex, assets := range inputAssets {
		assetTxs := make([]asset.Asset, 0)
		for _, a := range assets {
			assetTxs = append(assetTxs, asset.Asset{AssetID: a.AssetId, Amount: a.Amount})
		}
		assetsPrevout[inputIndex] = assetTxs
	}

	return asset.ValidateAssetTransaction(
		ctx, tx, assetsPrevout, assetSource{s.repoManager.Assets()},
	)
}

type assetSource struct {
	domain.AssetRepository
}

func (s assetSource) GetControlAsset(ctx context.Context, assetID string) (string, error) {
	assets, err := s.GetAssets(ctx, []string{assetID})
	if err != nil {
		return "", err
	}
	if len(assets) == 0 {
		return "", fmt.Errorf("no control asset found")
	}
	return assets[0].ControlAssetId, nil
}

func (s assetSource) AssetExists(ctx context.Context, assetID string) bool {
	_, err := s.GetAssets(ctx, []string{assetID})
	return err == nil
}
