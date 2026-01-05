package domain

import (
	"context"
)

type AssetRepository interface {
	InsertAssetAnchor(ctx context.Context, anchor AssetAnchor) error
	ListAssetAnchorsByAssetID(ctx context.Context, assetID string) ([]AssetAnchor, error)
	UpdateAssetMetadataList(ctx context.Context, assetId string, metadatalist []AssetMetadata) error
	InsertAssetGroup(ctx context.Context, assetGroup AssetGroup) error
	GetAssetByOutpoint(ctx context.Context, outpoint Outpoint) (*NormalAsset, error)
	GetAssetGroupByID(ctx context.Context, assetID string) (*AssetGroup, error)
	IncreaseAssetGroupQuantity(ctx context.Context, assetID string, amount uint64) error
	DecreaseAssetGroupQuantity(ctx context.Context, assetID string, amount uint64) error
	ListMetadataByAssetID(ctx context.Context, assetID string) ([]AssetMetadata, error)
	GetAssetAnchorByTxId(ctx context.Context, txId string) (*AssetAnchor, error)
	InsertTeleportAsset(ctx context.Context, teleport TeleportAsset) error
	GetTeleportAsset(ctx context.Context, teleportHash string) (*TeleportAsset, error)
	UpdateTeleportAsset(ctx context.Context, teleportHash string, isClaimed bool) error
	Close()
}
