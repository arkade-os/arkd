package domain

import (
	"context"
)

type AssetRepository interface {
	InsertAssetAnchor(ctx context.Context, anchor AssetAnchor) error
	ListAssetAnchorsByAssetID(ctx context.Context, assetID string) ([]AssetAnchor, error)
	InsertAssetGroup(ctx context.Context, assetGroup AssetGroup) error
	GetAssetByOutpoint(ctx context.Context, outpoint Outpoint) (*NormalAsset, error)
	GetAssetGroupByID(ctx context.Context, assetID string) (*AssetGroup, error)
	ListMetadataByAssetID(ctx context.Context, assetID string) ([]AssetMetadata, error)
	GetAssetAnchorByTxId(ctx context.Context, txId string) (*AssetAnchor, error)
	AddAssets(context.Context, []Asset) (int, error)
	GetAssets(context.Context, []string) ([]Asset, error)
	Close()
}
