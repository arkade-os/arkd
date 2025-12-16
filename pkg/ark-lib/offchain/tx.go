package offchain

import (
	"bytes"
	"fmt"
	"strings"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

const (
	// signal CLTV with input sequence number
	cltvSequence = wire.MaxTxInSequenceNum - 1
)

type VtxoInput struct {
	Outpoint *wire.OutPoint
	Amount   int64
	// Tapscript is the path used to spend the vtxo
	Tapscript *waddrmgr.Tapscript
	// RevealedTapscripts is the whole taproot tree of the vtxo
	// it must be revealed to the ark operator in order to verify the spent paths are valid
	RevealedTapscripts []string
}

// BuildTxs builds the ark and checkpoint txs for the given inputs and outputs.
func BuildTxs(
	vtxos []VtxoInput, outputs []*wire.TxOut, signerUnrollScript []byte,
) (*psbt.Packet, []*psbt.Packet, error) {
	checkpointInputs := make([]VtxoInput, 0, len(vtxos))
	checkpointTxs := make([]*psbt.Packet, 0, len(vtxos))
	inputAmount := int64(0)

	signerUnrollScriptClosure := &script.CSVMultisigClosure{}
	valid, err := signerUnrollScriptClosure.Decode(signerUnrollScript)
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		return nil, nil, fmt.Errorf("invalid signer unroll script")
	}

	for _, vtxo := range vtxos {
		checkpointPtx, checkpointInput, err := buildCheckpointTx(vtxo, signerUnrollScriptClosure)
		if err != nil {
			return nil, nil, err
		}

		checkpointInputs = append(checkpointInputs, *checkpointInput)
		checkpointTxs = append(checkpointTxs, checkpointPtx)
		inputAmount += vtxo.Amount
	}

	outputAmount := int64(0)
	for _, output := range outputs {
		outputAmount += output.Value
	}

	if inputAmount != outputAmount {
		return nil, nil, fmt.Errorf("input amount is not equal to output amount")
	}

	arkTx, err := buildArkTx(checkpointInputs, outputs)
	if err != nil {
		return nil, nil, err
	}

	return arkTx, checkpointTxs, nil
}

func BuildAssetTxs(outputs []*wire.TxOut, assetGroupIndex int, vtxos []VtxoInput, signerUnrollScript []byte) (*psbt.Packet, []*psbt.Packet, error) {
	checkpointInputs := make([]VtxoInput, 0, len(vtxos))
	checkpointTxs := make([]*psbt.Packet, 0, len(vtxos))

	assetAnchor := outputs[assetGroupIndex]

	assetGroup, err := asset.DecodeAssetGroupFromOpret(assetAnchor.PkScript)
	if err != nil {
		return nil, nil, err
	}

	signerUnrollScriptClosure := &script.CSVMultisigClosure{}
	valid, err := signerUnrollScriptClosure.Decode(signerUnrollScript)
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		return nil, nil, fmt.Errorf("invalid signer unroll script")
	}

	// Track which vtxos we used for the control asset so we don't reuse them for the normal asset.
	usedForControl := make([]bool, len(vtxos))

	// -------------------------
	// 1. Control asset handling
	// -------------------------
	updatedControlAssets := make([]asset.Asset, 0, len(assetGroup.ControlAssets))

	for _, controlAsset := range assetGroup.ControlAssets {
		controlAssetInputs := make([]asset.AssetInput, 0)

		for i, vtxo := range vtxos {
			if usedForControl[i] {
				continue
			}

			checkpointPtx, checkpointInput, assetOutput, err := buildAssetCheckpointTx(
				vtxo, i, &controlAsset, signerUnrollScriptClosure, assetGroup.SubDustKey,
			)
			if err != nil {
				return nil, nil, err
			}

			if assetOutput == nil {
				continue
			}

			txHash := checkpointPtx.UnsignedTx.TxHash()
			var commitment [32]byte
			copy(commitment[:], txHash[:])

			controlInput := asset.AssetInput{
				Type:       asset.AssetInputTypeTeleport,
				Commitment: commitment,
				Amount:     assetOutput.Amount,
			}

			controlAssetInputs = append(controlAssetInputs, controlInput)
			checkpointInputs = append(checkpointInputs, *checkpointInput)
			checkpointTxs = append(checkpointTxs, checkpointPtx)
			usedForControl[i] = true
		}

		if len(controlAssetInputs) == 0 {
			return nil, nil, fmt.Errorf("control asset vtxo not found for asset %x", controlAsset.AssetId)
		}
		controlAsset.Inputs = controlAssetInputs
		updatedControlAssets = append(updatedControlAssets, controlAsset)
	}

	// ------------------------
	// 2. Normal asset handling
	// ------------------------
	updatedNormalAssets := make([]asset.Asset, 0, len(assetGroup.NormalAssets))

	for _, normalAsset := range assetGroup.NormalAssets {
		normalAssetInputs := make([]asset.AssetInput, 0)

		for i, vtxo := range vtxos {
			// Don't reuse any vtxo that was already consumed
			if usedForControl[i] {
				continue
			}

			currentNormalAsset := normalAsset
			checkpointPtx, checkpointInput, assetOutput, err := buildAssetCheckpointTx(
				vtxo, i, &currentNormalAsset, signerUnrollScriptClosure, assetGroup.SubDustKey,
			)
			if err != nil {
				return nil, nil, err
			}

			if assetOutput != nil {
				txHash := checkpointPtx.UnsignedTx.TxHash()
				var commitment [32]byte
				copy(commitment[:], txHash[:])

				normalAssetInputs = append(normalAssetInputs, asset.AssetInput{
					Type:       asset.AssetInputTypeTeleport,
					Commitment: commitment,
					Amount:     assetOutput.Amount,
				})

				// We must add the checkpoint tx/input to the lists
				checkpointInputs = append(checkpointInputs, *checkpointInput)
				checkpointTxs = append(checkpointTxs, checkpointPtx)

				usedForControl[i] = true
			}
		}
		normalAsset.Inputs = normalAssetInputs
		updatedNormalAssets = append(updatedNormalAssets, normalAsset)
	}

	newAssetGroup := &asset.AssetGroup{
		ControlAssets: updatedControlAssets,
		NormalAssets:  updatedNormalAssets,
		SubDustKey:    assetGroup.SubDustKey,
	}

	newOpretOutput, err := newAssetGroup.EncodeOpret(assetAnchor.Value)
	if err != nil {
		return nil, nil, err
	}

	// Do NOT mutate caller's slice; work on a copy.
	copiedOutputs := make([]*wire.TxOut, len(outputs))
	copy(copiedOutputs, outputs)
	copiedOutputs[assetGroupIndex] = &newOpretOutput

	outputAmount := int64(0)
	for _, output := range outputs {
		outputAmount += output.Value
	}

	arkTx, err := buildArkTx(checkpointInputs, copiedOutputs)
	if err != nil {
		return nil, nil, err
	}

	return arkTx, checkpointTxs, nil

}

func RebuildAssetTxs(outputs []*wire.TxOut, assetGroupIndex int, checkpointTxMap map[string]string, vtxos []VtxoInput, signerUnrollScript []byte) (*psbt.Packet, []*psbt.Packet, error) {

	assetAnchor := outputs[assetGroupIndex]
	assetGroup, err := asset.DecodeAssetGroupFromOpret(assetAnchor.PkScript)
	if err != nil {
		return nil, nil, err
	}

	signerUnrollScriptClosure := &script.CSVMultisigClosure{}
	valid, err := signerUnrollScriptClosure.Decode(signerUnrollScript)
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		return nil, nil, fmt.Errorf("invalid signer unroll script")
	}

	controlAssets := assetGroup.ControlAssets
	normalAssets := assetGroup.NormalAssets

	// Helper to resolve inputs
	resolveInputs := func(inputs []asset.AssetInput) error {
		for i, input := range inputs {
			if input.Type != asset.AssetInputTypeTeleport {
				return fmt.Errorf("rebuild expects Teleport inputs (Checkpoint Hash), got %d", input.Type)
			}

			checkpointTxId, err := chainhash.NewHash(input.Commitment[:])
			if err != nil {
				return err
			}

			checkpointTxHex, ok := checkpointTxMap[checkpointTxId.String()]
			if !ok {
				return fmt.Errorf("checkpoint tx not found for asset input %s", checkpointTxId)
			}

			checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTxHex), true)
			if err != nil {
				return err
			}

			prev := checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint

			// Update the asset input to point to the underlying VTXO
			// We iterate through inputs slice pointer
			inputs[i].Type = asset.AssetInputTypeTeleport
			var vtxoHash [32]byte
			copy(vtxoHash[:], prev.Hash[:])
			inputs[i].Commitment = vtxoHash
		}
		return nil
	}

	// If control inputs are present, find the corresponding vtxos
	for i := range controlAssets {
		if err := resolveInputs(controlAssets[i].Inputs); err != nil {
			return nil, nil, err
		}
	}

	// -------------------------
	// 2. Normal asset inputs
	// -------------------------
	for i := range normalAssets {
		if err := resolveInputs(normalAssets[i].Inputs); err != nil {
			return nil, nil, err
		}
	}

	// -------------------------
	// 3. Encode updated assetGroup and build Asset Ark tx
	// -------------------------
	newAssetGroup := &asset.AssetGroup{
		ControlAssets: controlAssets,
		NormalAssets:  normalAssets,
		SubDustKey:    assetGroup.SubDustKey,
	}

	newOpretOutput, err := newAssetGroup.EncodeOpret(assetAnchor.Value)
	if err != nil {
		return nil, nil, err
	}

	outputs[assetGroupIndex] = &newOpretOutput

	return BuildAssetTxs(outputs, assetGroupIndex, vtxos, signerUnrollScript)
}

// buildArkTx builds an ark tx for the given vtxos and outputs.
// The ark tx is spending VTXOs using collaborative taproot path.
// An anchor output is added to the transaction
func buildArkTx(vtxos []VtxoInput, outputs []*wire.TxOut) (*psbt.Packet, error) {
	if len(vtxos) <= 0 {
		return nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]*wire.OutPoint, 0, len(vtxos))
	sequences := make([]uint32, 0, len(vtxos))
	witnessUtxos := make(map[int]*wire.TxOut)
	signingTapLeaves := make(map[int]*psbt.TaprootTapLeafScript)
	tapscripts := make(map[int][]string)
	txLocktime := common.AbsoluteLocktime(0)

	for index, vtxo := range vtxos {
		if len(vtxo.RevealedTapscripts) == 0 {
			return nil, fmt.Errorf("missing tapscripts for input %d", index)
		}

		tapscripts[index] = vtxo.RevealedTapscripts

		rootHash := vtxo.Tapscript.ControlBlock.RootHash(vtxo.Tapscript.RevealedScript)
		taprootKey := txscript.ComputeTaprootOutputKey(script.UnspendableKey(), rootHash)

		vtxoOutputScript, err := script.P2TRScript(taprootKey)
		if err != nil {
			return nil, err
		}

		witnessUtxos[index] = &wire.TxOut{
			Value:    vtxo.Amount,
			PkScript: vtxoOutputScript,
		}

		ctrlBlockBytes, err := vtxo.Tapscript.ControlBlock.ToBytes()
		if err != nil {
			return nil, err
		}

		signingTapLeaves[index] = &psbt.TaprootTapLeafScript{
			ControlBlock: ctrlBlockBytes,
			Script:       vtxo.Tapscript.RevealedScript,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		closure, err := script.DecodeClosure(vtxo.Tapscript.RevealedScript)
		if err != nil {
			return nil, err
		}

		// check if the closure is a CLTV multisig closure,
		// if so, update the tx locktime
		var locktime *common.AbsoluteLocktime
		if cltv, ok := closure.(*script.CLTVMultisigClosure); ok {
			locktime = &cltv.Locktime
			if locktime.IsSeconds() {
				if txLocktime != 0 && !txLocktime.IsSeconds() {
					return nil, fmt.Errorf("mixed absolute locktime types")
				}
			} else {
				if txLocktime != 0 && txLocktime.IsSeconds() {
					return nil, fmt.Errorf("mixed absolute locktime types")
				}
			}

			if *locktime > txLocktime {
				txLocktime = *locktime
			}
		}

		ins = append(ins, vtxo.Outpoint)
		if locktime != nil {
			sequences = append(sequences, cltvSequence)
		} else {
			sequences = append(sequences, wire.MaxTxInSequenceNum)
		}
	}

	arkTx, err := psbt.New(
		ins, append(outputs, txutils.AnchorOutput()), 3, uint32(txLocktime), sequences,
	)
	if err != nil {
		return nil, err
	}

	for i := range arkTx.Inputs {
		arkTx.Inputs[i].WitnessUtxo = witnessUtxos[i]
		arkTx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{signingTapLeaves[i]}

		if err := txutils.SetArkPsbtField(arkTx, i, txutils.VtxoTaprootTreeField, tapscripts[i]); err != nil {
			return nil, err
		}
	}

	return arkTx, nil
}

// buildCheckpointTx creates a virtual tx sending to a "checkpoint" vtxo script composed of
// the signer unroll script + the owner's collaborative closure.
func buildCheckpointTx(
	vtxo VtxoInput, signerUnrollScript *script.CSVMultisigClosure,
) (*psbt.Packet, *VtxoInput, error) {
	collaborativeClosure, err := script.DecodeClosure(vtxo.Tapscript.RevealedScript)
	if err != nil {
		return nil, nil, err
	}

	checkpointVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{signerUnrollScript, collaborativeClosure},
	}

	tapKey, tapTree, err := checkpointVtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	checkpointPkScript, err := script.P2TRScript(tapKey)
	if err != nil {
		return nil, nil, err
	}

	// build the checkpoint virtual tx
	checkpointPtx, err := buildArkTx(
		[]VtxoInput{vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}},
	)
	if err != nil {
		return nil, nil, err
	}

	// Now that we have the checkpoint tx, we need to return the corresponding output that will be
	// used as input for the ark tx.
	tapLeafHash := txscript.NewBaseTapLeaf(
		vtxo.Tapscript.RevealedScript,
	).TapHash()
	collaborativeLeafProof, err := tapTree.GetTaprootMerkleProof(tapLeafHash)
	if err != nil {
		return nil, nil, err
	}

	ctrlBlock, err := txscript.ParseControlBlock(collaborativeLeafProof.ControlBlock)
	if err != nil {
		return nil, nil, err
	}

	revealedTapscripts, err := checkpointVtxoScript.Encode()
	if err != nil {
		return nil, nil, err
	}

	checkpointInput := &VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  checkpointPtx.UnsignedTx.TxHash(),
			Index: 0,
		},
		Amount: vtxo.Amount,
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: collaborativeLeafProof.Script,
		},
		RevealedTapscripts: revealedTapscripts,
	}

	return checkpointPtx, checkpointInput, nil
}

// buildAssetCheckpointTx builds a checkpoint tx for an asset.
// vtxoIndex is the index of the vtxo in the vtxos slice passed to BuildAssetTxs.
func buildAssetCheckpointTx(
	vtxo VtxoInput, vtxoIndex int, assetData *asset.Asset, signerUnrollScript *script.CSVMultisigClosure, subDustKey *btcec.PublicKey,
) (*psbt.Packet, *VtxoInput, *asset.AssetOutput, error) {
	if vtxo.Tapscript == nil {
		return nil, nil, nil, fmt.Errorf("vtxo tapscript is nil")
	}

	collaborativeClosure, err := script.DecodeClosure(vtxo.Tapscript.RevealedScript)
	if err != nil {
		return nil, nil, nil, err
	}

	checkpointVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{signerUnrollScript, collaborativeClosure},
	}

	tapKey, tapTree, err := checkpointVtxoScript.TapTree()
	if err != nil {
		return nil, nil, nil, err
	}

	checkpointPkScript, err := script.P2TRScript(tapKey)
	if err != nil {
		return nil, nil, nil, err
	}

	var (
		isSeal       bool
		matchedInput asset.AssetInput
	)

	if assetData != nil {
		for _, in := range assetData.Inputs {
			switch in.Type {
			case asset.AssetInputTypeLocal:
				// Use Vin as index into vtxos
				if int(in.Vin) == vtxoIndex {
					isSeal = true
					matchedInput = in
				}
			case asset.AssetInputTypeTeleport:
				// Use Commitment as TxHash
				if bytes.Equal(in.Commitment[:], vtxo.Outpoint.Hash[:]) {
					isSeal = true
					matchedInput = in
				}
			}
			if isSeal {
				break
			}
		}
	}

	var (
		checkpointPtx *psbt.Packet
		assetOutput   *asset.AssetOutput
	)

	if !isSeal {
		checkpointPtx, err = buildArkTx(
			[]VtxoInput{vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}},
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("build plain checkpoint tx: %w", err)
		}

	} else {

		newAsset := *assetData
		// Create a new AssetInput pointing to the checkpoint
		// For the Ark Tx (Dest), we use Teleport type pointing to Checkpoint Hash.
		// However, here we just prepare the asset output for the checkpoint tx.
		// Wait, the asset output in checkpoint tx is correct.
		// But in BuildAssetTxs, we need to extract the Checkpoint Hash to put into Ark Tx Input.
		// Here we just replicate the input amount.

		newAsset.Inputs = []asset.AssetInput{
			{
				Type:   asset.AssetInputTypeLocal,
				Vin:    0,
				Amount: matchedInput.Amount,
			},
		}
		newAsset.Outputs = []asset.AssetOutput{
			{
				Type:   asset.AssetOutputTypeLocal,
				Amount: matchedInput.Amount,
				Vout:   0,
			},
		}
		assetOutput = &newAsset.Outputs[0]

		newAssetGroup := &asset.AssetGroup{
			ControlAssets: nil,
			NormalAssets:  []asset.Asset{newAsset},
			SubDustKey:    subDustKey,
		}

		assetOpret, err := newAssetGroup.EncodeOpret(0)
		if err != nil {
			return nil, nil, nil, err
		}

		checkpointPtx, err = buildArkTx(
			[]VtxoInput{vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}, &assetOpret},
		)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Now that we have the checkpoint tx, we need to return the corresponding output that will be
	// used as input for the ark tx.
	tapLeafHash := txscript.NewBaseTapLeaf(
		vtxo.Tapscript.RevealedScript,
	).TapHash()
	collaborativeLeafProof, err := tapTree.GetTaprootMerkleProof(tapLeafHash)
	if err != nil {
		return nil, nil, nil, err
	}

	ctrlBlock, err := txscript.ParseControlBlock(collaborativeLeafProof.ControlBlock)
	if err != nil {
		return nil, nil, nil, err
	}

	revealedTapscripts, err := checkpointVtxoScript.Encode()
	if err != nil {
		return nil, nil, nil, err
	}

	checkpointInput := &VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  checkpointPtx.UnsignedTx.TxHash(),
			Index: 0,
		},
		Amount: vtxo.Amount,
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: collaborativeLeafProof.Script,
		},
		RevealedTapscripts: revealedTapscripts,
	}

	return checkpointPtx, checkpointInput, assetOutput, nil

}
