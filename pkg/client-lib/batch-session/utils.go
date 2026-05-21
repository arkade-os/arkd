package batchsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func handleBatchEvents(
	ctx context.Context, customHandler batchsessionhandler.Handler,
	args batchsessionhandler.Args, notes []string,
	replayEventsCh chan<- any, cancelCh <-chan struct{},
) (string, string, time.Duration, []string, *tree.TxTree, error) {
	topics := make([]string, 0)
	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return "", "", -1, nil, nil, err
		}
		outpoint, _, err := parsedNote.IntentProofInput()
		if err != nil {
			return "", "", -1, nil, nil, err
		}
		topics = append(topics, outpoint.String())
	}

	for _, boardingUtxo := range args.BoardingUtxos {
		topics = append(topics, boardingUtxo.String())
	}
	for _, vtxo := range args.Vtxos {
		topics = append(topics, vtxo.Outpoint.String())
	}
	for _, signer := range args.SignerSessions {
		topics = append(topics, signer.GetPublicKey())
	}

	// Skip signing only if there are no offchain outputs
	skipVtxoTreeSigning := true
	for _, receiver := range args.Receivers {
		if _, err := arklib.DecodeAddressV0(receiver.To); err == nil {
			skipVtxoTreeSigning = false
			break
		}
	}

	options := []batchsessionhandler.HandlerOption{batchsessionhandler.WithCancel(cancelCh)}

	if skipVtxoTreeSigning {
		options = append(options, batchsessionhandler.WithSkipVtxoTreeSigning())
	}

	if replayEventsCh != nil {
		options = append(options, batchsessionhandler.WithReplay(replayEventsCh))
	}

	eventsCh, close, err := args.Client.GetEventStream(ctx, topics)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", "", -1, nil, nil, fmt.Errorf("connection closed by server")
		}
		return "", "", -1, nil, nil, err
	}
	defer close()

	batchEventsHandler := customHandler
	if batchEventsHandler == nil {
		batchEventsHandler, err = batchsessionhandler.NewDefaultHandler(args)
		if err != nil {
			return "", "", -1, nil, nil, err
		}
	}

	return batchsessionhandler.JoinBatchSession(ctx, eventsCh, batchEventsHandler, options...)
}

// toIntentInputs converts funds (boarding utxos, vtxos, or notes) into intent
// proof inputs and returns the auxiliary data needed to sign the proof PSBT.
func toIntentInputs(
	boardingUtxos []clientlib.Utxo, vtxos []clientlib.Vtxo, notes []string,
) ([]intent.Input, map[int][]clientlib.Asset, []*arklib.TaprootMerkleProof, [][]*psbt.Unknown, error) {
	inputs := make([]intent.Input, 0, len(boardingUtxos)+len(vtxos))
	signingLeaves := make([]*arklib.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	psbtFields := make([][]*psbt.Unknown, 0, len(boardingUtxos)+len(vtxos))
	assetInputs := make(map[int][]clientlib.Asset)

	for inputIndex, coin := range vtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := coin.ParseClosure()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})

		if len(coin.Assets) > 0 {
			// in context of intent transaction, there is a "fake" input at index 0
			// that's why from the asset packet point of view, the index must be i+1
			assetInputs[inputIndex+1] = coin.Assets
		}

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		psbtFields = append(psbtFields, []*psbt.Unknown{taptreeField})
	}

	for boardingIndex, coin := range boardingUtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := coin.ParseClosure()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})

		if len(coin.Assets) > 0 {
			// boarding utxos sit after vtxos in the proof PSBT, and the +1
			// accounts for the fake intent input at index 0.
			assetInputs[len(vtxos)+boardingIndex+1] = coin.Assets
		}

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		psbtFields = append(psbtFields, []*psbt.Unknown{taptreeField})
	}

	nextInputIndex := len(inputs)
	if nextInputIndex > 0 {
		// if there is non-notes inputs, count the extra intent proof input
		nextInputIndex++
	}

	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		outpoint, input, err := parsedNote.IntentProofInput()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    input.WitnessUtxo.Value,
				PkScript: input.WitnessUtxo.PkScript,
			},
		})

		vtxoScript := parsedNote.VtxoScript()

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		forfeitScript, err := vtxoScript.Closures[0].Script()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		nextInputIndex++
		// if the note vtxo is the first input, it will be used twice
		if nextInputIndex == 1 {
			nextInputIndex++
		}

		signingLeaves = append(signingLeaves, leafProof)
		psbtFields = append(psbtFields, input.Unknowns)
	}

	return inputs, assetInputs, signingLeaves, psbtFields, nil
}

// buildAndSignIntent build and signs an intent tx from the given args.
func buildAndSignIntent(
	ctx context.Context,
	message string, inputs []intent.Input, outputsTxOut []*wire.TxOut,
	leafProofs []*arklib.TaprootMerkleProof, arkFields [][]*psbt.Unknown,
	signingRequired bool, signTx func(context.Context, string) (string, error),
) (string, string, error) {
	proof, err := intent.New(message, inputs, outputsTxOut)
	if err != nil {
		return "", "", err
	}

	for i, input := range proof.Inputs {
		// intent proof tx has an additional input using the first vtxo script
		// so we need to use the previous leaf proof for the current input except for the first input
		var leafProof *arklib.TaprootMerkleProof
		if i == 0 {
			leafProof = leafProofs[0]
		} else {
			leafProof = leafProofs[i-1]
			input.Unknowns = arkFields[i-1]
		}
		input.TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: leafProof.ControlBlock,
				Script:       leafProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}

		proof.Inputs[i] = input
	}

	unsignedProofTx, err := proof.B64Encode()
	if err != nil {
		return "", "", err
	}

	if !signingRequired {
		return unsignedProofTx, message, nil
	}

	signedTx, err := signTx(ctx, unsignedProofTx)
	if err != nil {
		return "", "", err
	}

	return signedTx, message, nil
}

// registerIntentMessage creates the message for registring for a batch session.
func registerIntentMessage(
	assetInputs map[int][]clientlib.Asset, outputs []clientlib.Receiver, cosignersPublicKeys []string,
) (string, []*wire.TxOut, extension.Extension, error) {
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)

	for i, output := range outputs {
		txOut, isOnchain, err := output.ToTxOut()
		if err != nil {
			return "", nil, nil, err
		}

		if isOnchain {
			onchainOutputsIndexes = append(onchainOutputsIndexes, i)
		}

		outputsTxOut = append(outputsTxOut, txOut)
	}

	var ext extension.Extension
	if len(assetInputs) > 0 {
		assetPacket, err := createAssetPacket(assetInputs, outputs, nil)
		if err != nil {
			return "", nil, nil, err
		}

		ext = extension.Extension{assetPacket}
		assetPacketOutput, err := ext.TxOut()
		if err != nil {
			return "", nil, nil, err
		}
		outputsTxOut = append(outputsTxOut, assetPacketOutput)
	}

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: onchainOutputsIndexes,
		CosignersPublicKeys:  cosignersPublicKeys,
	}.Encode()
	if err != nil {
		return "", nil, nil, err
	}

	return message, outputsTxOut, ext, nil
}

// createAssetPacket computes the right packet for the given asset inputs and receivers
func createAssetPacket(
	assetInputs map[int][]clientlib.Asset,
	receivers []clientlib.Receiver, changeReceiver *clientlib.Receiver,
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
				assetTransfers[ass.AssetId].outputs, *output,
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
			assetId, nil, inputsOutputs.inputs, inputsOutputs.outputs, nil,
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

// filterVtxosByExpiry returns vtxos that have expiry equal or below the given threshold
func filterVtxosByExpiry(vtxos []clientlib.Vtxo, expiryThreshold int64) []clientlib.Vtxo {
	now := time.Now()
	threshold := time.Duration(expiryThreshold) * time.Second

	nearExpiry := make([]clientlib.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		// Time until expiry
		timeLeft := vtxo.ExpiresAt.Sub(now)

		// If already expired or within threshold
		if timeLeft <= threshold {
			nearExpiry = append(nearExpiry, vtxo)
		}
	}

	return nearExpiry
}
