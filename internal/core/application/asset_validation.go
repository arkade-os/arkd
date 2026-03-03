package application

import (
	"context"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func (s *service) validateAssetTransaction(
	ctx context.Context, tx *wire.MsgTx, inputAssets map[int][]domain.AssetDenomination,
	ignoreMissingAssetPackets bool,
) errors.Error {
	assetsPrevout := make(map[int][]asset.Asset)
	for inputIndex, assets := range inputAssets {
		assetTxs := make([]asset.Asset, 0)
		for _, a := range assets {
			assetTxs = append(assetTxs, asset.Asset(a))
		}
		assetsPrevout[inputIndex] = assetTxs
	}

	if err := asset.ValidateAssetTransaction(
		ctx, tx, assetsPrevout, assetSource{s.repoManager.Assets()},
	); err != nil {
		// When the flag is set, suppress only the "asset packet not found"
		// branch of ASSET_VALIDATION_FAILED and let all other errors through.
		if ignoreMissingAssetPackets &&
			err.CodeName() == "ASSET_VALIDATION_FAILED" &&
			strings.Contains(err.Error(), "asset packet not found") {
			return nil
		}
		return err
	}

	// getAssetsFromTx returns nil when no asset packet is present (e.g. when
	// ignoreMissingAssetPackets caused the early return above). The loop below
	// handles a nil map gracefully by simply not iterating.
	assets, err := getAssetsFromTx(&psbt.Packet{UnsignedTx: tx})
	if err != nil {
		return nil
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
	for _, group := range packet {
		if group.IsIssuance() {
			return true
		}
	}
	return false
}
