package application

import (
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/wire"
)

func (s *service) validateAssetTransaction(
	ctx context.Context,
	tx *wire.MsgTx,
	ext extension.Extension,
	inputAssets map[int][]domain.AssetDenomination,
) errors.Error {
	assetsPrevout := make(map[int][]asset.Asset)
	for inputIndex, assets := range inputAssets {
		assetTxs := make([]asset.Asset, 0)
		for _, a := range assets {
			assetTxs = append(assetTxs, asset.Asset(a))
		}
		assetsPrevout[inputIndex] = assetTxs
	}

	assetPacket := ext.GetAssetPacket()

	if err := asset.ValidateAssetTransaction(
		ctx, tx, assetPacket, assetsPrevout, assetSource{s.repoManager.Assets()},
	); err != nil {
		return err
	}

	assets, err := getAssetsDenominations(assetPacket, tx.TxID())
	if err != nil {
		return errors.INTERNAL_ERROR.Wrap(err)
	}

	for vout, denominations := range assets {
		if len(denominations) > s.maxAssetsPerVtxo {
			return errors.VTXO_WITH_TOO_MANY_ASSETS.New(
				"output %d has %d assets, exceeds max %d",
				vout, len(denominations), s.maxAssetsPerVtxo,
			).WithMetadata(errors.VtxoWithTooManyAssetsMetadata{
				AssetCount: len(denominations),
				MaxAssets:  s.maxAssetsPerVtxo,
			})
		}
	}

	return nil
}

type assetSource struct {
	domain.AssetRepository
}

func (s assetSource) AssetExists(ctx context.Context, assetID string) bool {
	exists, err := s.AssetRepository.AssetExists(ctx, assetID)
	return err == nil && exists
}

func hasIssuance(packet asset.Packet) bool {
	if len(packet) == 0 {
		return false
	}

	for _, group := range packet {
		if group.IsIssuance() {
			return true
		}
	}
	return false
}
