package arksdk

import (
	"bytes"
	"context"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	log "github.com/sirupsen/logrus"
)

func (a *service) SendOffChain(
	ctx context.Context, receivers []types.Receiver, opts ...SendOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	if len(receivers) <= 0 {
		return "", fmt.Errorf("missing receivers")
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", err
	}

	expectedSignerPubkey := schnorr.SerializePubKey(a.SignerPubKey)
	sumOfReceivers := uint64(0)

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", fmt.Errorf("all receiver addresses must be offchain addresses")
		}

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvSignerPubkey := schnorr.SerializePubKey(addr.Signer)
		if !bytes.Equal(expectedSignerPubkey, rcvSignerPubkey) {
			return "", fmt.Errorf(
				"invalid receiver address '%s': expected signer pubkey %x, got %x",
				receiver.To, expectedSignerPubkey, rcvSignerPubkey,
			)
		}

		sumOfReceivers += receiver.Amount
	}

	options := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", err
		}
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	vtxos := options.vtxos
	if len(vtxos) <= 0 {
		spendableVtxos, err := a.getSpendableVtxos(ctx, &getVtxosFilter{
			withoutExpirySorting: options.withoutExpirySorting,
		})
		if err != nil {
			return "", err
		}

		for _, offchainAddr := range offchainAddrs {
			for _, v := range spendableVtxos {
				if v.IsRecoverable() {
					continue
				}

				vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
				if err != nil {
					return "", err
				}

				if vtxoAddr == offchainAddr.Address {
					vtxos = append(vtxos, types.VtxoWithTapTree{
						Vtxo:       v,
						Tapscripts: offchainAddr.Tapscripts,
					})
				}
			}
		}
	}

	// do not include boarding utxos
	_, selectedCoins, changeAmount, err := utils.CoinSelect(
		nil, vtxos, receivers, a.Dust, options.withoutExpirySorting, nil,
	)
	if err != nil {
		return "", err
	}

	if changeAmount > 0 {
		receivers = append(receivers, types.Receiver{
			To: offchainAddrs[0].Address, Amount: changeAmount,
		})
	}

	inputs := make([]arkTxInput, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		vtxoScript, err := script.ParseVtxoScript(coin.Tapscripts)
		if err != nil {
			return "", err
		}

		forfeitClosure := vtxoScript.ForfeitClosures()[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return "", err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)

		inputs = append(inputs, arkTxInput{
			coin,
			forfeitLeaf.TapHash(),
		})
	}

	arkTx, checkpointTxs, err := buildOffchainTx(inputs, receivers, a.CheckpointExitPath(), a.Dust)
	if err != nil {
		return "", err
	}

	signedArkTx, err := a.wallet.SignTransaction(ctx, a.explorer, arkTx)
	if err != nil {
		return "", err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, a.SignerPubKey); err != nil {
		return "", err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, a.SignerPubKey); err != nil {
		return "", err
	}

	return a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	})
}

func (a *service) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	return a.finalizePendingTxs(ctx, createdAfter)
}

func (a *service) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	vtxos, err := a.fetchPendingSpentVtxos(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if createdAfter != nil && !createdAfter.IsZero() {
			if !vtxo.CreatedAt.After(*createdAfter) {
				continue
			}
		}
		filtered = append(filtered, vtxo)
	}

	if len(filtered) == 0 {
		return nil, nil
	}

	vtxosWithTapscripts, err := a.populateVtxosWithTapscripts(ctx, filtered)
	if err != nil {
		return nil, err
	}

	inputs, exitLeaves, arkFields, err := toIntentInputs(nil, vtxosWithTapscripts, nil)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0)
	const MAX_INPUTS_PER_INTENT = 20

	for i := 0; i < len(inputs); i += MAX_INPUTS_PER_INTENT {
		end := min(i+MAX_INPUTS_PER_INTENT, len(inputs))
		inputsSubset := inputs[i:end]
		exitLeavesSubset := exitLeaves[i:end]
		arkFieldsSubset := arkFields[i:end]
		proofTx, message, err := a.makeGetPendingTxIntent(
			inputsSubset, exitLeavesSubset, arkFieldsSubset,
		)
		if err != nil {
			return nil, err
		}

		pendingTxs, err := a.client.GetPendingTx(ctx, proofTx, message)
		if err != nil {
			return nil, err
		}

		for _, tx := range pendingTxs {
			txid, err := a.finalizeTx(ctx, tx)
			if err != nil {
				log.WithError(err).Errorf("failed to finalize pending tx: %s", tx.Txid)
				continue
			}
			txids = append(txids, txid)
		}
	}

	return txids, nil
}

func (a *service) finalizeTx(
	ctx context.Context, acceptedTx client.AcceptedOffchainTx,
) (string, error) {
	finalCheckpoints := make([]string, 0, len(acceptedTx.SignedCheckpointTxs))

	for _, checkpoint := range acceptedTx.SignedCheckpointTxs {
		signedTx, err := a.wallet.SignTransaction(ctx, a.explorer, checkpoint)
		if err != nil {
			return "", err
		}
		finalCheckpoints = append(finalCheckpoints, signedTx)
	}

	if err := a.client.FinalizeTx(ctx, acceptedTx.Txid, finalCheckpoints); err != nil {
		return "", err
	}

	return acceptedTx.Txid, nil
}
