package domain

import (
	"context"
)

type AssetRepository interface {
	AddAssets(ctx context.Context, assetsByTx, assetsByIntent map[string][]Asset) (int, error)
	GetAssets(ctx context.Context, assetIds []string) ([]Asset, error)
	Close()
}
