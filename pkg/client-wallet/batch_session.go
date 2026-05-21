package wallet

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
)

func (w *wallet) Settle(
	ctx context.Context, opts ...batchsession.Option,
) (*SettleRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	info, err := w.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	vtxos, err := w.getSpendableVtxos(ctx, nil)
	if err != nil {
		return nil, err
	}
	// coinselect all available boarding utxos and vtxos
	boardingUtxos, err := w.getClaimableBoardingUtxos(ctx)
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

	return batchsession.Settle(ctx, batchsession.SettleArgs{
		Client:        w.client,
		ServerInfo:    *info,
		SignTx:        signTx,
		BoardingUtxos: boardingUtxos,
		Vtxos:         vtxos,
		ReceiverAddr:  offchainAddr.Address,
	}, opts...)
}

func (w *wallet) RedeemNotes(
	ctx context.Context, notes []string, opts ...batchsession.Option,
) (*RedeemNotesRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	info, err := w.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	return batchsession.RedeemNotes(ctx, batchsession.RedeemNotesArgs{
		Client:       w.client,
		ServerInfo:   *info,
		SignTx:       signTx,
		Notes:        notes,
		ReceiverAddr: offchainAddr.Address,
	}, opts...)
}

func (w *wallet) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...batchsession.Option,
) (*CollaborativeExitRes, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	if w.UtxoMaxAmount == 0 {
		return nil, fmt.Errorf("operation not allowed by the server")
	}

	w.txLock.Lock()
	defer w.txLock.Unlock()

	// send all case: substract fees from exited amount
	info, err := w.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	_, offchainAddr, _, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	feeEstimator, err := arkfee.New(info.Fees.IntentFees)
	if err != nil {
		return nil, err
	}

	vtxos, err := w.getSpendableVtxos(ctx, nil)
	if err != nil {
		return nil, err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	return batchsession.CollaborativeExit(ctx, batchsession.CollaborativeExitArgs{
		Client:       w.client,
		SignTx:       signTx,
		FeeEstimator: feeEstimator,
		ServerInfo:   *info,
		Vtxos:        vtxos,
		Receiver:     clientlib.Receiver{To: addr, Amount: amount},
		ChangeAddr:   offchainAddr.Address,
	}, opts...)
}

func (w *wallet) RegisterIntent(
	ctx context.Context, vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo, notes []string,
	outputs []clientlib.Receiver, cosignersPublicKeys []string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	_, offchainAddr, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return "", err
	}

	myVtxos, myBoardingUtxos, err := w.populateVtxosWithTapscripts(
		ctx, vtxos, boardingUtxos, offchainAddr, boardingAddr,
	)
	if err != nil {
		return "", err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	proofTx, message, _, err := batchsession.BuildAndSignRegisterIntent(
		ctx, batchsession.IntentArgs{
			Cosigners: cosignersPublicKeys,
			BaseArgs: batchsession.BaseArgs{
				Vtxos:         myVtxos,
				BoardingUtxos: myBoardingUtxos,
				Notes:         notes,
				Outputs:       outputs,
				SignTx:        signTx,
			},
		},
	)
	if err != nil {
		return "", err
	}

	return w.client.RegisterIntent(ctx, proofTx, message)
}

func (w *wallet) DeleteIntent(
	ctx context.Context, vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo, notes []string,
) error {
	if err := w.safeCheck(); err != nil {
		return err
	}

	_, offchainAddr, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return err
	}

	myVtxos, myBoardingUtxos, err := w.populateVtxosWithTapscripts(
		ctx, vtxos, boardingUtxos, offchainAddr, boardingAddr,
	)
	if err != nil {
		return err
	}

	signTx := func(ctx context.Context, tx string) (string, error) {
		return w.identity.SignTransaction(ctx, tx, nil)
	}

	proofTx, message, err := batchsession.BuildAndSignDeleteIntent(
		ctx, batchsession.IntentArgs{BaseArgs: batchsession.BaseArgs{
			Vtxos:         myVtxos,
			BoardingUtxos: myBoardingUtxos,
			Notes:         notes,
			SignTx:        signTx,
		}},
	)
	if err != nil {
		return err
	}

	return w.client.DeleteIntent(ctx, proofTx, message)
}

func (w *wallet) getClaimableBoardingUtxos(ctx context.Context) ([]clientlib.Utxo, error) {
	_, _, boardingAddr, _, err := w.getAddresses(ctx)
	if err != nil {
		return nil, err
	}

	return w.getUtxos(ctx, *boardingAddr, getUtxosFilter{claimable: true})
}
