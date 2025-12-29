package domain

import (
	"context"
)

type AssetRepository interface {
	InsertAssetAnchor(ctx context.Context, anchor AssetAnchor) error
	ListAssetAnchorsByAssetID(ctx context.Context, assetID string) ([]AssetAnchor, error)
	UpdateAssetMetadataList(ctx context.Context, assetId string, metadatalist []AssetMetadata) error
	InsertAssetDetails(ctx context.Context, assetDetails AssetDetails) error
	GetAssetByOutpoint(ctx context.Context, outpoint Outpoint) (*NormalAsset, error)
	GetAssetDetailsByID(ctx context.Context, assetID string) (*AssetDetails, error)
	IncreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error
	DecreaseAssetQuantity(ctx context.Context, assetID string, amount uint64) error
	ListMetadataByAssetID(ctx context.Context, assetID string) ([]AssetMetadata, error)
	GetAssetAnchorByTxId(ctx context.Context, txId string) (*AssetAnchor, error)
	InsertTeleportAsset(ctx context.Context, teleport TeleportAsset) error
	GetTeleportAsset(ctx context.Context, teleportHash string) (*TeleportAsset, error)
	UpdateTeleportAsset(ctx context.Context, teleportHash string, isClaimed bool) error
	Close()
}
