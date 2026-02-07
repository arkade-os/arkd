package domain

import (
	"context"
)

type AssetRepository interface {
	AddAssets(ctx context.Context, assetsByTx map[string][]Asset) (int, error)
	GetAssets(ctx context.Context, assetIds []string) ([]Asset, error)
	GetControlAsset(ctx context.Context, assetID string) (string, error)
	AssetExists(ctx context.Context, assetID string) (bool, error)
	Close()
}
