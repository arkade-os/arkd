package wallet

import (
	"context"
	"fmt"

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

	vtxos, err := w.getSpendableVtxos(ctx, nil)
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

	return offchaintx.IssueAsset(ctx, offchaintx.IssueAssetArgs{
		BuildAndSignIssuanceTxArgs: offchaintx.BuildAndSignIssuanceTxArgs{
			BaseArgs: offchaintx.BaseArgs{
				ServerInfo: w.Config.ClientInfo(),
				SignTx:     signTx,
				Vtxos:      vtxos,
				ChangeAddr: offchainAddr.Address,
			},
			Amount:       amount,
			ControlAsset: controlAsset,
			Metadata:     metadata,
		},
		Client: w.client,
	}, opts...)
}

func (w *wallet) ReissueAsset(
	ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
) (*ReissueAssetRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	controlAssetId, err := w.getControlAssetId(ctx, assetId)
	if err != nil {
		return nil, fmt.Errorf("failed to get control asset: %w", err)
	}
	if controlAssetId == "" {
		return nil, fmt.Errorf("%s can't be reissued, no control asset", assetId)
	}

	vtxos, err := w.getSpendableVtxos(ctx, nil)
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
		BuildAndSignReissuanceTxArgs: offchaintx.BuildAndSignReissuanceTxArgs{
			BaseArgs: offchaintx.BaseArgs{
				ServerInfo: w.Config.ClientInfo(),
				SignTx:     signTx,
				Vtxos:      vtxos,
				ChangeAddr: offchainAddr.Address,
			},
			AssetId:        assetId,
			ControlAssetId: controlAssetId,
			Amount:         amount,
		},
		Client: w.client,
	}, opts...)
}

func (w *wallet) BurnAsset(
	ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
) (*BurnAssetRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	vtxos, err := w.getSpendableVtxos(ctx, nil)
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
		BuildAndSignBurnTxArgs: offchaintx.BuildAndSignBurnTxArgs{
			BaseArgs: offchaintx.BaseArgs{
				ServerInfo: w.Config.ClientInfo(),
				SignTx:     signTx,
				Vtxos:      vtxos,
				ChangeAddr: offchainAddr.Address,
			},
			AssetId: assetId,
			Amount:  amount,
		},
		Client: w.client,
	}, opts...)
}

func (w *wallet) getControlAssetId(ctx context.Context, assetId string) (string, error) {
	indexerAssetInfo, err := w.indexer.GetAsset(ctx, assetId)
	if err != nil {
		return "", fmt.Errorf("failed to fetch asset from indexer: %w", err)
	}
	return indexerAssetInfo.ControlAssetId, nil
}
