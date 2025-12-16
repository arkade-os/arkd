package domain

import (
	"context"
)

type AssetRepository interface {
	InsertAssetAnchor(ctx context.Context, anchor AssetAnchor) error
	UpdateAssetMetadataList(ctx context.Context, assetId string, metadatalist []AssetMetadata) error
	InsertAsset(ctx context.Context, asset Asset) error
	GetAssetByID(ctx context.Context, assetID string) (*Asset, error)
	IncreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error
	DecreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error
	ListMetadataByAssetID(ctx context.Context, assetID string) ([]AssetMetadata, error)
	GetAssetAnchorByTxId(ctx context.Context, txId string) (*AssetAnchor, error)
	InsertTeleportAsset(ctx context.Context, teleport TeleportAsset) error
	GetTeleportAsset(ctx context.Context, teleportHash string) (*TeleportAsset, error)
	UpdateTeleportAsset(ctx context.Context, teleportHash string, isClaimed bool) error
	Close()
}
