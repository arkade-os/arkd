package wallet

import (
	"context"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
)

func (w *wallet) SendOffChain(
	ctx context.Context, receivers []clientlib.Receiver, opts ...offchaintx.Option,
) (*SendOffChainRes, error) {
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

	return offchaintx.Send(ctx, offchaintx.SendArgs{
		Client:       w.client,
		ServerParams: *w.ServerParams,
		SignTx:       signTx,
		Vtxos:        vtxos,
		ChangeAddr:   offchainAddr.Address,
		Receivers:    receivers,
	}, opts...)
}

func (w *wallet) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	vtxos, err := w.getPendingVtxos(ctx, createdAfter)
	if err != nil {
		return nil, err
	}

	if len(vtxos) <= 0 {
		return nil, nil
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	return offchaintx.FinalizePendingTxs(ctx, offchaintx.FinalizePendingTxsArgs{
		Client:       w.client,
		SignTx:       signTx,
		Vtxos:        vtxos,
		CreatedAfter: createdAfter,
	})
}
