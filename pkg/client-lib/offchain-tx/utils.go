package offchaintx

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type arkTxInput struct {
	clientlib.Vtxo
	ForfeitLeafHash chainhash.Hash
}

func buildOffchainTx(
	vtxos []arkTxInput, receivers []clientlib.Receiver, serverUnrollScript []byte, dustLimit uint64,
) (string, []string, error) {
	if len(vtxos) <= 0 {
		return "", nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, err
		}

		tapscript := &waddrmgr.Tapscript{
			RevealedScript: leafProof.Script,
			ControlBlock:   ctrlBlock,
		}

		ins = append(ins, offchain.VtxoInput{
			Outpoint:           vtxoOutpoint,
			Tapscript:          tapscript,
			Amount:             int64(vtxo.Amount),
			RevealedTapscripts: vtxo.Tapscripts,
		})
	}

	outs := make([]*wire.TxOut, 0, len(receivers))

	for i, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", nil, fmt.Errorf("receiver %d is onchain", i)
		}

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, err
		}

		var newVtxoScript []byte

		if receiver.Amount < dustLimit {
			newVtxoScript, err = script.SubDustScript(addr.VtxoTapKey)
		} else {
			newVtxoScript, err = script.P2TRScript(addr.VtxoTapKey)
		}
		if err != nil {
			return "", nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: newVtxoScript,
		})
	}

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
	if err != nil {
		return "", nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, nil
}

func selectedCoinsToAssetInputs(selectedCoins []clientlib.Vtxo) map[int][]clientlib.Asset {
	assetInputs := make(map[int][]clientlib.Asset)
	for inputIndex, coin := range selectedCoins {
		if len(coin.Assets) == 0 {
			continue
		}
		assetInputs[inputIndex] = coin.Assets
	}
	return assetInputs
}

// createAssetPacket computes the right packet for the given asset inputs and receivers
func createAssetPacket(
	assetInputs map[int][]clientlib.Asset, receivers []clientlib.Receiver, changeReceiver *clientlib.Receiver,
) (asset.Packet, error) {
	if changeReceiver != nil {
		receivers = append(receivers, *changeReceiver)
	}

	type assetTransfer struct {
		inputs  []asset.AssetInput
		outputs []asset.AssetOutput
	}

	assetTransfers := make(map[string]*assetTransfer)
	for inputIndex, assets := range assetInputs {
		for _, a := range assets {
			if _, exists := assetTransfers[a.AssetId]; !exists {
				assetTransfers[a.AssetId] = &assetTransfer{
					inputs:  make([]asset.AssetInput, 0),
					outputs: make([]asset.AssetOutput, 0),
				}
			}

			input, err := asset.NewAssetInput(uint16(inputIndex), a.Amount)
			if err != nil {
				return nil, err
			}
			assetTransfers[a.AssetId].inputs = append(
				assetTransfers[a.AssetId].inputs,
				*input,
			)
		}
	}

	for receiverIndex, receiver := range receivers {
		if len(receiver.Assets) == 0 {
			continue
		}

		for _, ass := range receiver.Assets {
			if _, exists := assetTransfers[ass.AssetId]; !exists {
				return nil, fmt.Errorf("asset %s not found", ass.AssetId)
			}

			output, err := asset.NewAssetOutput(uint16(receiverIndex), ass.Amount)
			if err != nil {
				return nil, err
			}
			assetTransfers[ass.AssetId].outputs = append(
				assetTransfers[ass.AssetId].outputs,
				*output,
			)
		}
	}

	assetGroups := make([]asset.AssetGroup, 0)
	for assetId, inputsOutputs := range assetTransfers {
		assetId, err := asset.NewAssetIdFromString(assetId)
		if err != nil {
			return nil, err
		}

		assetGroup, err := asset.NewAssetGroup(
			assetId,
			nil,
			inputsOutputs.inputs,
			inputsOutputs.outputs,
			nil,
		)
		if err != nil {
			return nil, err
		}
		assetGroups = append(assetGroups, *assetGroup)
	}

	if len(assetGroups) == 0 {
		return nil, nil
	}

	return asset.NewPacket(assetGroups)
}

// addExtension inserts an extension OP_RETURN (asset packet + extras) right
// before the P2A anchor output, which remains last. If both assetPacket and
// extraPkts are empty it is a no-op. Duplicate packet types are rejected.
func addExtension(
	ptx *psbt.Packet, assetPacket asset.Packet, extraPkts []extension.Packet,
) error {
	// Nothing to add when we have neither an asset packet nor extras.
	if len(assetPacket) == 0 && len(extraPkts) == 0 {
		return nil
	}

	pkts := make([]extension.Packet, 0, 1+len(extraPkts))
	if len(assetPacket) > 0 {
		pkts = append(pkts, assetPacket)
	}
	pkts = append(pkts, extraPkts...)

	ext, err := extension.NewExtensionFromPackets(pkts...)
	if err != nil {
		return err
	}

	packetOut, err := ext.TxOut()
	if err != nil {
		return fmt.Errorf("building extension txout: %w", err)
	}
	// Insert the extension output immediately before the P2A anchor, keeping
	// ptx.Outputs[i] aligned with ptx.UnsignedTx.TxOut[i]. The anchor's own
	// PSBT-level metadata must follow its TxOut to the new last index; the
	// fresh empty POutput goes next to the EXT TxOut.
	lastIdx := len(ptx.UnsignedTx.TxOut) - 1
	p2aTxOut := ptx.UnsignedTx.TxOut[lastIdx]
	p2aPOutput := ptx.Outputs[lastIdx]
	ptx.UnsignedTx.TxOut[lastIdx] = packetOut
	ptx.Outputs[lastIdx] = psbt.POutput{}
	ptx.UnsignedTx.TxOut = append(ptx.UnsignedTx.TxOut, p2aTxOut)
	ptx.Outputs = append(ptx.Outputs, p2aPOutput)
	return nil
}

// verifyOffchainTx verifies the signer signatures of the given transaction
func verifyOffchainTx(original, signed *psbt.Packet, signerPubkey *btcec.PublicKey) error {
	xonlySigner := schnorr.SerializePubKey(signerPubkey)

	if original.UnsignedTx.TxID() != signed.UnsignedTx.TxID() {
		return fmt.Errorf("invalid offchain tx : txids mismatch")
	}

	if len(original.Inputs) != len(signed.Inputs) {
		return fmt.Errorf(
			"input count mismatch: expected %d, got %d",
			len(original.Inputs),
			len(signed.Inputs),
		)
	}

	if len(original.UnsignedTx.TxIn) != len(signed.UnsignedTx.TxIn) {
		return fmt.Errorf(
			"transaction input count mismatch: expected %d, got %d",
			len(original.UnsignedTx.TxIn),
			len(signed.UnsignedTx.TxIn),
		)
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for inputIndex, signedInput := range signed.Inputs {
		if signedInput.WitnessUtxo == nil {
			return fmt.Errorf("witness utxo not found for input %d", inputIndex)
		}

		// fill prevouts map with the original witness data
		previousOutpoint := original.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		prevouts[previousOutpoint] = original.Inputs[inputIndex].WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsigHashes := txscript.NewTxSigHashes(original.UnsignedTx, prevoutFetcher)

	// loop over every input and check that the signer's signature is present and valid
	for inputIndex, signedInput := range signed.Inputs {
		originalInput := original.Inputs[inputIndex]
		if len(originalInput.TaprootLeafScript) == 0 {
			return fmt.Errorf(
				"original input %d has no taproot leaf script, cannot verify signature",
				inputIndex,
			)
		}

		// check that every input has the signer's signature
		var signerSig *psbt.TaprootScriptSpendSig

		for _, sig := range signedInput.TaprootScriptSpendSig {
			if bytes.Equal(sig.XOnlyPubKey, xonlySigner) {
				signerSig = sig
				break
			}
		}

		if signerSig == nil {
			return fmt.Errorf("signer signature not found for input %d", inputIndex)
		}

		sig, err := schnorr.ParseSignature(signerSig.Signature)
		if err != nil {
			return fmt.Errorf("failed to parse signer signature for input %d: %s", inputIndex, err)
		}

		// verify the signature
		message, err := txscript.CalcTapscriptSignaturehash(
			txsigHashes,
			signedInput.SighashType,
			original.UnsignedTx,
			inputIndex,
			prevoutFetcher,
			txscript.NewBaseTapLeaf(originalInput.TaprootLeafScript[0].Script),
		)
		if err != nil {
			return err
		}

		if !sig.Verify(message, signerPubkey) {
			return fmt.Errorf("invalid signer signature for input %d", inputIndex)
		}
	}
	return nil
}

// createOffchainTx selects coins, computes change, and assembles the base
// (unsigned, no asset packet) ark tx + checkpoint txs.
func createOffchainTx(
	_ context.Context, args BaseArgs, receivers []clientlib.Receiver,
) (string, []string, []clientlib.Vtxo, *clientlib.Receiver, error) {
	if len(receivers) <= 0 {
		return "", nil, nil, nil, fmt.Errorf("missing receivers")
	}

	checkpointExitPath, err := args.checkpointExitPath()
	if err != nil {
		return "", nil, nil, nil, err
	}

	signerPubKey, err := args.signerPubKey()
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("invalid signer pubkey: %w", err)
	}
	expectedSignerPubkey := schnorr.SerializePubKey(signerPubKey)

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

	btcAmountToSelect := int64(0)
	selectedCoins := make([]clientlib.Vtxo, 0)
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

				availableVtxos := make([]clientlib.Vtxo, 0, len(args.Vtxos))
				for _, v := range args.Vtxos {
					if !selectedVtxos[v.Outpoint.String()] {
						availableVtxos = append(availableVtxos, v)
					}
				}

				assetCoins, assetChangeAmount, err := utils.CoinSelectAsset(
					availableVtxos, amountToSelect, asset.AssetId, false,
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
		availableVtxos := make([]clientlib.Vtxo, 0, len(args.Vtxos))
		for _, v := range args.Vtxos {
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
				btcAmountToSelect = int64(args.ServerInfo.Dust)
			}

			_, selectedBtcCoins, changeBtcAmount, err := utils.CoinSelect(
				nil, availableVtxos,
				// use a "fake" receiver to select only the remaining btc amount
				// it works for offchain tx because feeEstimator is nil (no offchain fee)
				[]clientlib.Receiver{{Amount: uint64(btcAmountToSelect)}},
				args.ServerInfo.Dust, nil,
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
				changeAmount = changeBtcAmount + args.ServerInfo.Dust
			}
		}
	} else {
		changeAmount = uint64(math.Abs(float64(btcAmountToSelect)))
	}

	var changeReceiver *clientlib.Receiver

	// enforce a minimum change amount when there are asset changes
	if len(assetChanges) > 0 && changeAmount == 0 {
		// build a set of already-selected coin outpoints to avoid double-selection
		selectedOutpoints := make(map[string]struct{})
		for _, coin := range selectedCoins {
			selectedOutpoints[coin.Txid+fmt.Sprintf(":%d", coin.VOut)] = struct{}{}
		}

		availableVtxos := make([]clientlib.Vtxo, 0)
		for _, vtxo := range args.Vtxos {
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
			nil, availableVtxos, []clientlib.Receiver{{Amount: args.ServerInfo.Dust}},
			args.ServerInfo.Dust, nil,
		)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf(
				"failed to select coins for asset change output: %w",
				err,
			)
		}

		selectedCoins = append(selectedCoins, selectedBtcCoins...)
		changeAmount = changeBtcAmount + args.ServerInfo.Dust
	}

	if changeAmount > 0 {
		changeReceiver = &clientlib.Receiver{
			To: args.ChangeAddr, Amount: changeAmount,
		}
		if len(assetChanges) > 0 {
			for assetID, amount := range assetChanges {
				if amount > 0 {
					changeReceiver.Assets = append(changeReceiver.Assets, clientlib.Asset{
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

	arkTx, checkpointTxs, err := buildOffchainTx(
		inputs, receivers, checkpointExitPath, args.ServerInfo.Dust,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	return arkTx, checkpointTxs, selectedCoins, changeReceiver, nil
}

// submitAndFinalize submits the signed ark + unsigned checkpoint txs to the server,
// verifies the server's counter-signatures, and finalizes by sending the fully signed checkpoints.
// Returns the final ark txid, the fully-signed ark tx, and  checkpoint txs.
// Shared by every orchestrator (Send, IssueAsset, ReissueAsset, BurnAsset).
func submitAndFinalize(
	ctx context.Context, c clientlib.Client, signTx SignFn,
	signerPubKey *btcec.PublicKey, build *BuildAndSignTxRes,
) (string, string, []string, error) {
	arkTxid, signedArk, signedCps, err := c.SubmitTx(
		ctx, build.SignedArkTx, build.CheckpointTxs,
	)
	if err != nil {
		return "", "", nil, err
	}

	if err := VerifySignedTx(build.ArkTx, signedArk, signerPubKey); err != nil {
		return "", "", nil, err
	}
	if err := VerifySignedCheckpointTxs(build.CheckpointTxs, signedCps, signerPubKey); err != nil {
		return "", "", nil, err
	}

	txid, finalCps, err := finalizeTx(ctx, c, signTx, clientlib.AcceptedOffchainTx{
		Txid:                arkTxid,
		FinalArkTx:          signedArk,
		SignedCheckpointTxs: signedCps,
	})
	if err != nil {
		return "", "", nil, err
	}

	return txid, signedArk, finalCps, nil
}

// finalizeTx signs the server-returned checkpoint txs with signTx, calls
// FinalizeTx on the client, and returns the ark txid plus the finalized
// checkpoint txs.
func finalizeTx(
	ctx context.Context, c clientlib.Client, signTx SignFn,
	acceptedTx clientlib.AcceptedOffchainTx,
) (string, []string, error) {
	finalCheckpoints := make([]string, 0, len(acceptedTx.SignedCheckpointTxs))

	for _, checkpoint := range acceptedTx.SignedCheckpointTxs {
		signedTx, err := signTx(ctx, checkpoint)
		if err != nil {
			return "", nil, err
		}
		finalCheckpoints = append(finalCheckpoints, signedTx)
	}

	if err := c.FinalizeTx(ctx, acceptedTx.Txid, finalCheckpoints); err != nil {
		return "", nil, err
	}

	return acceptedTx.Txid, finalCheckpoints, nil
}

// parsePubkey converts a hex-encoded pubkey to a btcec.PublicKey.
func parsePubkey(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(buf)
}
