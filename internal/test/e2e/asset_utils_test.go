package e2e_test

import (
	"context"
	"fmt"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
)

func fetchAssetVtxo(
	ctx context.Context,
	client arksdk.ArkClient,
	assetID string,
	amount uint64,
) (types.Vtxo, error) {
	vtxos, err := client.ListSpendableVtxos(ctx)
	if err != nil {
		return types.Vtxo{}, err
	}

	for _, vtxo := range vtxos {
		if len(vtxo.Assets) > 0 && vtxo.Assets[0].AssetId == assetID {
			if amount == 0 || vtxo.Assets[0].Amount >= amount {
				return vtxo, nil
			}
		}
	}

	return types.Vtxo{}, fmt.Errorf("no suitable vtxo found for asset %s", assetID)
}
