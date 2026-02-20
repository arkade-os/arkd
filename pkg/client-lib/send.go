package arksdk

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	log "github.com/sirupsen/logrus"
)

func (a *service) SendOffChain(
	ctx context.Context, receivers []types.Receiver, opts ...SendOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, opts...,
	)
	if err != nil {
		return "", err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return "", err
	}

	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, changeReceiver,
	)
	if err != nil {
		return "", err
	}

	if err := addAssetPacket(arkPtx, assetPacket); err != nil {
		return "", err
	}

	arkTx, err := arkPtx.B64Encode()
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

func (a *service) createOffchainTx(
	ctx context.Context, receivers []types.Receiver, opts ...SendOption,
) (string, []string, []types.VtxoWithTapTree, *types.Receiver, error) {
	if len(receivers) <= 0 {
		return "", nil, nil, nil, fmt.Errorf("missing receivers")
	}

	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if len(offchainAddrs) == 0 {
		return "", nil, nil, nil, fmt.Errorf("no offchain addresses")
	}

	expectedSignerPubkey := schnorr.SerializePubKey(a.SignerPubKey)

	for _, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", nil, nil, nil, fmt.Errorf(
				"all receiver addresses must be offchain addresses",
			)
		}

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("invalid receiver address: %s", err)
		}

		rcvSignerPubkey := schnorr.SerializePubKey(addr.Signer)
		if !bytes.Equal(expectedSignerPubkey, rcvSignerPubkey) {
			return "", nil, nil, nil, fmt.Errorf(
				"invalid receiver address '%s': expected signer pubkey %x, got %x",
				receiver.To, expectedSignerPubkey, rcvSignerPubkey,
			)
		}
	}

	options := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return "", nil, nil, nil, err
		}
	}

	vtxos := make([]types.VtxoWithTapTree, 0)
	spendableVtxos, err := a.getSpendableVtxos(ctx, &getVtxosFilter{
		withoutExpirySorting: options.withoutExpirySorting,
	})
	if err != nil {
		return "", nil, nil, nil, err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			if v.IsRecoverable() {
				continue
			}

			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return "", nil, nil, nil, err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, types.VtxoWithTapTree{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	btcAmountToSelect := int64(0)
	selectedCoins := make([]types.VtxoWithTapTree, 0)
	assetChanges := make(map[string]uint64)
	selectedVtxos := make(map[string]bool)

	for _, receiver := range receivers {
		btcAmountToSelect += int64(receiver.Amount)

		if len(receiver.Assets) > 0 {
			for _, asset := range receiver.Assets {
				amountToSelect := asset.Amount
				existingChangeAmount := assetChanges[asset.AssetId]
				if existingChangeAmount > 0 {
					if amountToSelect <= existingChangeAmount {
						// change covers the needed amount, no need to select any more coins
						assetChanges[asset.AssetId] -= amountToSelect
						if assetChanges[asset.AssetId] == 0 {
							delete(assetChanges, asset.AssetId)
						}
						continue
					} else {
						// change does not cover the needed amount, select the remaining amount
						amountToSelect -= existingChangeAmount
						delete(assetChanges, asset.AssetId)
					}
				}

				availableVtxos := make([]types.VtxoWithTapTree, 0, len(vtxos))
				for _, v := range vtxos {
					if !selectedVtxos[v.Outpoint.String()] {
						availableVtxos = append(availableVtxos, v)
					}
				}

				assetCoins, assetChangeAmount, err := utils.CoinSelectAsset(
					availableVtxos, amountToSelect, asset.AssetId, options.withoutExpirySorting,
				)
				if err != nil {
					return "", nil, nil, nil, err
				}

				for _, coin := range assetCoins {
					coinID := coin.Outpoint.String()
					selectedVtxos[coinID] = true
					selectedCoins = append(selectedCoins, coin)

					// asset coins contain btc, subtract it from the total amount to select
					btcAmountToSelect -= int64(coin.Amount)

					// coin may contain other assets, add them to the asset changes
					for _, a := range coin.Assets {
						if a.AssetId == asset.AssetId {
							continue
						}
						assetChanges[a.AssetId] += a.Amount
					}
				}
				if assetChangeAmount > 0 {
					assetChanges[asset.AssetId] += assetChangeAmount
				}
			}
		}
	}

	changeAmount := uint64(0)

	if btcAmountToSelect >= 0 {
		isZero := btcAmountToSelect == 0

		// filter out already-selected vtxos
		availableVtxos := make([]types.VtxoWithTapTree, 0, len(vtxos))
		for _, v := range vtxos {
			if !selectedVtxos[v.Outpoint.String()] {
				availableVtxos = append(availableVtxos, v)
			}
		}

		// skip BTC coin selection if all BTC was covered by asset coins
		// and there are no more available vtxos (send-all scenario)
		if isZero && len(availableVtxos) == 0 {
			changeAmount = 0
		} else {
			if isZero {
				btcAmountToSelect = int64(a.Dust)
			}

			_, selectedBtcCoins, changeBtcAmount, err := utils.CoinSelect(
				nil, availableVtxos,
				// use a "fake" receiver to select only the remaining btc amount
				// it works for offchain tx because feeEstimator is nil (no offchain fee)
				[]types.Receiver{{Amount: uint64(btcAmountToSelect)}},
				a.Dust, options.withoutExpirySorting, nil,
			)
			if err != nil {
				return "", nil, nil, nil, err
			}

			// some coins may contain assets, add them to the asset changes
			for _, coin := range selectedBtcCoins {
				for _, asset := range coin.Assets {
					if asset.Amount > 0 {
						assetChanges[asset.AssetId] += asset.Amount
					}
				}
			}

			selectedCoins = append(selectedCoins, selectedBtcCoins...)
			changeAmount = changeBtcAmount
			if isZero {
				changeAmount = changeBtcAmount + a.Dust
			}
		}
	} else {
		changeAmount = uint64(math.Abs(float64(btcAmountToSelect)))
	}

	var changeReceiver *types.Receiver

	// enforce a minimum change amount when there are asset changes
	if len(assetChanges) > 0 && changeAmount == 0 {
		// build a set of already-selected coin outpoints to avoid double-selection
		selectedOutpoints := make(map[string]struct{})
		for _, coin := range selectedCoins {
			selectedOutpoints[coin.Txid+fmt.Sprintf(":%d", coin.VOut)] = struct{}{}
		}

		availableVtxos := make([]types.VtxoWithTapTree, 0)
		for _, vtxo := range vtxos {
			outpoint := vtxo.Outpoint.String()
			if _, selected := selectedOutpoints[outpoint]; selected {
				continue
			}
			// only include vtxos without assets
			if len(vtxo.Assets) == 0 {
				availableVtxos = append(availableVtxos, vtxo)
			}
		}

		_, selectedBtcCoins, changeBtcAmount, err := utils.CoinSelect(
			nil, availableVtxos, []types.Receiver{{Amount: a.Dust}},
			a.Dust, options.withoutExpirySorting, nil,
		)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf(
				"failed to select coins for asset change output: %w",
				err,
			)
		}

		selectedCoins = append(selectedCoins, selectedBtcCoins...)
		changeAmount = changeBtcAmount + a.Dust
	}

	if changeAmount > 0 {
		changeReceiver = &types.Receiver{
			To: offchainAddrs[0].Address, Amount: changeAmount,
		}
		if len(assetChanges) > 0 {
			for assetID, amount := range assetChanges {
				if amount > 0 {
					changeReceiver.Assets = append(changeReceiver.Assets, types.Asset{
						AssetId: assetID,
						Amount:  amount,
					})
				}
			}
		}

		receivers = append(receivers, *changeReceiver)
	}

	inputs := make([]arkTxInput, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		vtxoScript, err := script.ParseVtxoScript(coin.Tapscripts)
		if err != nil {
			return "", nil, nil, nil, err
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) == 0 {
			return "", nil, nil, nil, fmt.Errorf("no forfeit closures found")
		}
		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return "", nil, nil, nil, err
		}

		forfeitLeafHash := txscript.NewBaseTapLeaf(forfeitScript).TapHash()

		inputs = append(inputs, arkTxInput{coin, forfeitLeafHash})
	}

	arkTx, checkpointTxs, err := buildOffchainTx(inputs, receivers, a.CheckpointExitPath(), a.Dust)
	if err != nil {
		return "", nil, nil, nil, err
	}

	return arkTx, checkpointTxs, selectedCoins, changeReceiver, nil
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

	inputs, exitLeaves, arkFields, _, err := toIntentInputs(nil, vtxosWithTapscripts, nil)
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
