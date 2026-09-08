package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
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
) (*SendOffChainRes, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	o := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt.applySend(o); err != nil {
			return nil, err
		}
	}

	a.txLock.Lock()
	defer a.txLock.Unlock()

	cfgData, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	baseArkTx, checkpointTxs, selectedCoins, changeReceiver, err := a.createOffchainTx(
		ctx, receivers, o,
	)
	if err != nil {
		return nil, err
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(baseArkTx), true)
	if err != nil {
		return nil, err
	}

	assetPacket, err := createAssetPacket(
		selectedCoinsToAssetInputs(selectedCoins), receivers, changeReceiver,
	)
	if err != nil {
		return nil, err
	}

	if err := addExtension(arkPtx, assetPacket, o.extraPackets); err != nil {
		return nil, err
	}

	if err := applyOutputTapTrees(arkPtx, o.outputsTapTree); err != nil {
		return nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedArkTx, err := a.identity.SignTransaction(ctx, arkTx, o.signingKeys)
	if err != nil {
		return nil, err
	}

	arkTxid, signedArkTx, signedCheckpointTxs, err := a.client.SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return nil, err
	}

	signers := cfgData.AllSigners()
	// validate and verify transactions returned by the server
	if err := verifySignedArk(arkTx, signedArkTx, signers); err != nil {
		return nil, err
	}

	if err := verifySignedCheckpoints(checkpointTxs, signedCheckpointTxs, signers); err != nil {
		return nil, err
	}

	txid, checkpointTxs, err := a.finalizeTx(ctx, client.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArkTx,
		SignedCheckpointTxs: signedCheckpointTxs,
	}, o.signingKeys)
	if err != nil {
		return nil, err
	}

	ins := make([]types.Vtxo, 0, len(selectedCoins))
	for _, c := range selectedCoins {
		ins = append(ins, c.Vtxo)
	}
	outs := make([]types.Receiver, 0)
	if changeReceiver != nil {
		outs = append(outs, *changeReceiver)
	}

	ext := make(extension.Extension, 0, 1+len(o.extraPackets))
	if len(assetPacket) > 0 {
		ext = append(ext, assetPacket)
	}
	ext = append(ext, o.extraPackets...)

	return &SendOffChainRes{
		Txid:        txid,
		Tx:          signedArkTx,
		Checkpoints: checkpointTxs,
		Inputs:      ins,
		Outputs:     outs,
		Extension:   ext,
	}, nil
}

func (a *service) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time, opts ...SendOption,
) ([]string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	o := newDefaultSendOptions()
	for _, opt := range opts {
		if err := opt.applySend(o); err != nil {
			return nil, err
		}
	}

	return a.finalizePendingTxs(ctx, createdAfter, o.vtxos, o.signingKeys)
}

func (a *service) createOffchainTx(
	ctx context.Context, receivers []types.Receiver, opts *sendOptions,
) (string, []string, []types.VtxoWithTapTree, *types.Receiver, error) {
	if len(receivers) <= 0 {
		return "", nil, nil, nil, fmt.Errorf("missing receivers")
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

	vtxos := make([]types.VtxoWithTapTree, 0)
	if len(opts.vtxos) > 0 {
		vtxos = slices.Clone(opts.vtxos)
	} else {
		_, offchainAddrs, _, _, err := a.getAddresses(ctx)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if len(offchainAddrs) == 0 {
			return "", nil, nil, nil, fmt.Errorf("no offchain addresses")
		}

		spendableVtxos, err := a.getSpendableVtxos(ctx, &getVtxosFilter{
			withoutExpirySorting: opts.withoutExpirySorting,
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
					availableVtxos, amountToSelect, asset.AssetId, opts.withoutExpirySorting,
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

	// filter out already-selected vtxos
	availableVtxos := make([]types.VtxoWithTapTree, 0, len(vtxos))
	for _, v := range vtxos {
		if !selectedVtxos[v.Outpoint.String()] {
			availableVtxos = append(availableVtxos, v)
		}
	}

	// The change has to be spendable as a vtxo, so it can never fall below the
	// dust limit, whatever minimum the caller asked for.
	minChangeAmount := max(a.Dust, opts.minChangeAmount)

	// An asset change needs an output to ride on. Keep leaving a change output
	// too when the asset coins cover the receivers exactly and there is still
	// something to select, unless this is a send-all.
	needChange := len(assetChanges) > 0 ||
		(btcAmountToSelect == 0 && len(availableVtxos) > 0)

	selectedBtcCoins, changeAmount, err := selectChangeCoins(
		btcAmountToSelect, needChange, availableVtxos,
		minChangeAmount, opts.withoutExpirySorting,
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

	var changeReceiver *types.Receiver

	// a coin selected for its btc may itself carry assets: their change needs
	// an output to ride on, so make room for one if the btc side left none.
	if len(assetChanges) > 0 && changeAmount == 0 {
		// build a set of already-selected coin outpoints to avoid double-selection
		selectedOutpoints := make(map[string]struct{})
		for _, coin := range selectedCoins {
			selectedOutpoints[coin.Outpoint.String()] = struct{}{}
		}

		assetFreeVtxos := make([]types.VtxoWithTapTree, 0)
		for _, vtxo := range vtxos {
			if _, selected := selectedOutpoints[vtxo.Outpoint.String()]; selected {
				continue
			}
			// only include vtxos without assets, to not add yet more changes
			if len(vtxo.Assets) == 0 {
				assetFreeVtxos = append(assetFreeVtxos, vtxo)
			}
		}

		moreCoins, change, err := selectChangeCoins(
			0, true, assetFreeVtxos, minChangeAmount, opts.withoutExpirySorting,
		)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf(
				"failed to select coins for asset change output: %w",
				err,
			)
		}

		selectedCoins = append(selectedCoins, moreCoins...)
		changeAmount = change
	}

	if changeAmount > 0 {
		addr, err := a.getReceiver(ctx, opts.receiver)
		if err != nil {
			return "", nil, nil, nil, err
		}

		changeReceiver = &types.Receiver{
			To: addr, Amount: changeAmount,
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

// selectChangeCoins selects the extra vtxos needed to settle the btc side of an
// offchain tx, and returns them along with the resulting change.
//
// btcAmountToSelect is what the receivers ask for minus the btc already riding
// on the coins selected to cover the asset amounts. A negative value means
// those coins carry a surplus, which is change we hold before selecting
// anything further.
//
// An offchain tx conserves value exactly, so a surplus can never be given up,
// and the server rejects any output below its min vtxo amount: the change is
// therefore either exactly 0 or at least minChangeAmount, and when it can't be
// either the send fails here rather than at the server. needChange forces a
// change output even when the btc side balances out, so that an asset change
// has an output to ride on.
func selectChangeCoins(
	btcAmountToSelect int64, needChange bool, availableVtxos []types.VtxoWithTapTree,
	minChangeAmount uint64, withoutExpirySorting bool,
) ([]types.VtxoWithTapTree, uint64, error) {
	changeAmount := uint64(0)
	if btcAmountToSelect < 0 {
		changeAmount = uint64(-btcAmountToSelect)
		btcAmountToSelect = 0
		needChange = true
	}

	// pull in the sats missing to lift the change up to the minimum
	if needChange && changeAmount < minChangeAmount {
		btcAmountToSelect += int64(minChangeAmount - changeAmount)
		changeAmount = minChangeAmount
	}

	if btcAmountToSelect <= 0 {
		return nil, changeAmount, nil
	}

	_, selected, extraChange, err := utils.CoinSelect(
		nil, availableVtxos,
		// use a "fake" receiver to select only the remaining btc amount
		// it works for offchain tx because feeEstimator is nil (no offchain fee)
		[]types.Receiver{{Amount: uint64(btcAmountToSelect)}},
		minChangeAmount, withoutExpirySorting, nil, minChangeAmount,
	)
	if err != nil {
		return nil, 0, err
	}

	return selected, changeAmount + extraChange, nil
}

func (a *service) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
	vtxosWithTapscripts []types.VtxoWithTapTree, keysByScript map[string]string,
) ([]string, error) {
	if len(vtxosWithTapscripts) <= 0 {
		vtxos, err := a.fetchPendingSpentVtxos(ctx)
		if err != nil {
			return nil, err
		}
		vtxosWithTapscripts, err = a.populateVtxosWithTapscripts(ctx, vtxos)
		if err != nil {
			return nil, err
		}
	}

	filtered := make([]types.VtxoWithTapTree, 0, len(vtxosWithTapscripts))
	for _, vtxo := range vtxosWithTapscripts {
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

	inputs, exitLeaves, arkFields, _, err := toIntentInputs(nil, filtered, nil)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0)
	const MAX_INPUTS_PER_INTENT = 20
	signingRequired := true

	for i := 0; i < len(inputs); i += MAX_INPUTS_PER_INTENT {
		end := min(i+MAX_INPUTS_PER_INTENT, len(inputs))
		inputsSubset := inputs[i:end]
		exitLeavesSubset := exitLeaves[i:end]
		arkFieldsSubset := arkFields[i:end]
		proofTx, message, err := a.makeGetPendingTxIntent(
			inputsSubset, exitLeavesSubset, arkFieldsSubset, signingRequired, keysByScript,
		)
		if err != nil {
			return nil, err
		}

		pendingTxs, err := a.client.GetPendingTx(ctx, proofTx, message)
		if err != nil {
			return nil, err
		}

		for _, tx := range pendingTxs {
			txid, _, err := a.finalizeTx(ctx, tx, keysByScript)
			if err != nil {
				log.WithError(err).Errorf("failed to finalize pending tx: %s", tx.Txid)
				continue
			}
			txids = append(txids, txid)
		}
	}

	return txids, nil
}

// applyOutputTapTrees sets the BIP-371 TaprootTapTree field on every PSBT
// output whose hex-encoded pkScript matches a key in byPkScript. An error is
// returned when a key matches no output: silently ignoring an unmatched key
// would let a caller think the tree was set on the wire while the PSBT goes
// out without it — a footgun in a VTXO-spending path.
func applyOutputTapTrees(ptx *psbt.Packet, taprootTrees map[string][]byte) error {
	if len(taprootTrees) <= 0 {
		return nil
	}
	if len(ptx.UnsignedTx.TxOut) != len(ptx.Outputs) {
		return fmt.Errorf(
			"output count mismatch: unsigned tx has %d outputs but ptx has %d",
			len(ptx.UnsignedTx.TxOut), len(ptx.Outputs),
		)
	}
	matched := make(map[string]bool, len(taprootTrees))
	for i, out := range ptx.UnsignedTx.TxOut {
		pkHex := hex.EncodeToString(out.PkScript)
		tapTree, ok := taprootTrees[pkHex]
		if !ok {
			continue
		}
		ptx.Outputs[i].TaprootTapTree = tapTree
		matched[pkHex] = true
	}
	if len(matched) == len(taprootTrees) {
		return nil
	}
	unmatched := make([]string, 0, len(taprootTrees)-len(matched))
	for k := range taprootTrees {
		if !matched[k] {
			unmatched = append(unmatched, k)
		}
	}
	sort.Strings(unmatched)
	return fmt.Errorf(
		"no matching output for pkScript(s): %s", strings.Join(unmatched, ", "),
	)
}

func (a *service) finalizeTx(
	ctx context.Context, acceptedTx client.AcceptedOffchainTx, keysByScript map[string]string,
) (string, []string, error) {
	finalCheckpoints := make([]string, 0, len(acceptedTx.SignedCheckpointTxs))

	for _, checkpoint := range acceptedTx.SignedCheckpointTxs {
		signedTx, err := a.identity.SignTransaction(ctx, checkpoint, keysByScript)
		if err != nil {
			return "", nil, err
		}
		finalCheckpoints = append(finalCheckpoints, signedTx)
	}

	if err := a.client.FinalizeTx(ctx, acceptedTx.Txid, finalCheckpoints); err != nil {
		return "", nil, err
	}

	return acceptedTx.Txid, finalCheckpoints, nil
}
