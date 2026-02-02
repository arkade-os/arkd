package domain

import (
	"context"
)

type AssetAnchor struct {
	Outpoint
	Assets []NormalAsset
}

type AssetMetadata struct {
	Key   string
	Value string
}

type NormalAsset struct {
	Outpoint
	Amount  uint64
	AssetID string
}

// TODO: rename, misleading with ark-lib asset_group.go
type AssetGroup struct {
	ID             string
	Quantity       uint64
	Immutable      bool
	ControlAssetID string
	Metadata       []AssetMetadata
}

type TeleportAsset struct {
	Script      string
	IntentID    string
	AssetID     string
	OutputIndex uint32
	Amount      uint64
	IsClaimed   bool
}

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
	GetTeleportAsset(
		ctx context.Context,
		script string,
		intentID string,
		assetID string,
		outputIndex uint32,
	) (*TeleportAsset, error)
	UpdateTeleportAsset(
		ctx context.Context,
		script string,
		intentID string,
		assetID string,
		outputIndex uint32,
		isClaimed bool,
	) error
	Close()
}
