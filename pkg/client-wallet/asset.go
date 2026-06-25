package wallet

import (
	"context"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
)

func (w *wallet) IssueAsset(
	ctx context.Context, amount uint64, controlAsset clientlib.ControlAsset,
	metadata []asset.Metadata, opts ...offchaintx.Option,
) (*IssueAssetRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	vtxos, err := w.getSpendableVtxos(ctx, &getVtxosFilter{excludeRecoverableVtxos: true})
	if err != nil {
		return nil, err
	}

	ctrlAsset := controlAsset
	if c, ok := ctrlAsset.(clientlib.ExistingControlAsset); ok {
		ctrlAssetAmount := uint64(0)
		for _, v := range vtxos {
			if i := slices.IndexFunc(v.Assets, func(asset clientlib.Asset) bool {
				return asset.AssetId == c.Id
			}); i >= 0 {
				ctrlAssetAmount += v.Assets[i].Amount
			}
		}
		ctrlAsset = clientlib.ExistingControlAsset{
			Id:     c.Id,
			Amount: ctrlAssetAmount,
		}
	}

	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	return offchaintx.IssueAsset(ctx, offchaintx.IssueAssetArgs{
		Client:       w.client,
		ServerParams: *w.ServerParams,
		SignTx:       signTx,
		Vtxos:        vtxos,
		ChangeAddr:   offchainAddr.Address,
		Amount:       amount,
		ControlAsset: ctrlAsset,
		Metadata:     metadata,
	}, opts...)
}

func (w *wallet) ReissueAsset(
	ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
) (*ReissueAssetRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	controlAsset, err := w.getControlAsset(ctx, assetId)
	if err != nil {
		return nil, fmt.Errorf("failed to get control asset: %w", err)
	}
	if controlAsset == nil {
		return nil, fmt.Errorf("%s can't be reissued, no control asset", assetId)
	}

	vtxos, err := w.getSpendableVtxos(ctx, &getVtxosFilter{excludeRecoverableVtxos: true})
	if err != nil {
		return nil, err
	}

	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	return offchaintx.ReissueAsset(ctx, offchaintx.ReissueAssetArgs{
		Client:       w.client,
		ServerParams: *w.ServerParams,
		SignTx:       signTx,
		Vtxos:        vtxos,
		ChangeAddr:   offchainAddr.Address,
		Asset: clientlib.Asset{
			AssetId: assetId,
			Amount:  amount,
		},
		ControlAsset: *controlAsset,
	}, opts...)
}

func (w *wallet) BurnAsset(
	ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
) (*BurnAssetRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	vtxos, err := w.getSpendableVtxos(ctx, &getVtxosFilter{excludeRecoverableVtxos: true})
	if err != nil {
		return nil, err
	}

	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	return offchaintx.BurnAsset(ctx, offchaintx.BurnAssetArgs{
		Client:       w.client,
		ServerParams: *w.ServerParams,
		SignTx:       signTx,
		Vtxos:        vtxos,
		ChangeAddr:   offchainAddr.Address,
		Asset: clientlib.Asset{
			AssetId: assetId,
			Amount:  amount,
		},
	}, opts...)
}

func (w *wallet) getControlAsset(ctx context.Context, assetId string) (*clientlib.Asset, error) {
	info, err := w.indexer.GetAsset(ctx, assetId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch asset data: %w", err)
	}
	controlAssetInfo, err := w.indexer.GetAsset(ctx, info.ControlAssetId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch control asset data: %w", err)
	}
	return &clientlib.Asset{
		AssetId: controlAssetInfo.AssetId,
		Amount:  controlAssetInfo.Supply,
	}, nil
}
