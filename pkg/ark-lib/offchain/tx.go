package offchain

import (
	"bytes"
	"fmt"
	"strings"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
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

	// Track which vtxos we used so we don't reuse them.
	usedVtxos := make([]bool, len(vtxos))

	// -------------------------
	// 1. Control asset handling
	// -------------------------
	updatedControlAssets := make([]asset.AssetGroup, 0, len(assetGroup.ControlAssets))

	for _, controlAsset := range assetGroup.ControlAssets {
		controlAssetInputs := make([]asset.AssetInput, 0)

		for _, input := range controlAsset.Inputs {
			if input.Type == asset.AssetTypeTeleport {
				controlAssetInputs = append(controlAssetInputs, input)
				continue
			}

			//get asset seal
			var vtxoInput *VtxoInput
			for i, vtxo := range vtxos {
				if usedVtxos[i] {
					continue
				}

				if vtxo.Outpoint.Index == uint32(input.Vin) && bytes.Equal(vtxo.Outpoint.Hash[:], input.Hash) {
					vtxoInput = &vtxos[i]
					usedVtxos[i] = true
					break
				}
			}

			if vtxoInput == nil {
				return nil, nil, fmt.Errorf("vtxo not found for input %d", input.Vin)
			}

			checkpointPtx, checkpointInput, err := buildAssetCheckpointTx(
				vtxoInput, &input, signerUnrollScriptClosure,
			)
			if err != nil {
				return nil, nil, err
			}

			txHash := checkpointPtx.UnsignedTx.TxHash()
			controlInput := asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    0,
				Hash:   txHash.CloneBytes(),
				Amount: input.Amount,
			}

			controlAssetInputs = append(controlAssetInputs, controlInput)
			checkpointInputs = append(checkpointInputs, *checkpointInput)
			checkpointTxs = append(checkpointTxs, checkpointPtx)

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
	updatedNormalAssets := make([]asset.AssetGroup, 0, len(assetGroup.NormalAssets))

	for _, normalAsset := range assetGroup.NormalAssets {
		normalAssetInputs := make([]asset.AssetInput, 0)

		for _, input := range normalAsset.Inputs {
			if input.Type == asset.AssetTypeTeleport {
				normalAssetInputs = append(normalAssetInputs, input)
				continue
			}

			//get asset seal
			var vtxoInput *VtxoInput
			for i, vtxo := range vtxos {
				if usedVtxos[i] {
					continue
				}

				if vtxo.Outpoint.Index == uint32(input.Vin) && bytes.Equal(vtxo.Outpoint.Hash[:], input.Hash) {
					vtxoInput = &vtxos[i]
					usedVtxos[i] = true
					break
				}
			}
			if vtxoInput == nil {
				return nil, nil, fmt.Errorf("vtxo not found for input %d (normal asset)", input.Vin)
			}

			checkpointPtx, checkpointInput, err := buildAssetCheckpointTx(
				vtxoInput, &input, signerUnrollScriptClosure,
			)
			if err != nil {
				return nil, nil, err
			}

			txHash := checkpointPtx.UnsignedTx.TxHash()
			controlInput := asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    0,
				Hash:   txHash.CloneBytes(),
				Amount: input.Amount,
			}

			normalAssetInputs = append(normalAssetInputs, controlInput)
			checkpointInputs = append(checkpointInputs, *checkpointInput)
			checkpointTxs = append(checkpointTxs, checkpointPtx)
		}
		normalAsset.Inputs = normalAssetInputs
		updatedNormalAssets = append(updatedNormalAssets, normalAsset)
	}

	// ------------------------
	// 3. Handle remaining VTXOs (plain inputs)
	// ------------------------
	for i, vtxo := range vtxos {
		if usedVtxos[i] {
			continue
		}

		checkpointPtx, checkpointInput, err := buildCheckpointTx(
			vtxo, signerUnrollScriptClosure,
		)
		if err != nil {
			return nil, nil, err
		}

		checkpointInputs = append(checkpointInputs, *checkpointInput)
		checkpointTxs = append(checkpointTxs, checkpointPtx)
	}

	newAssetGroup := &asset.AssetPacket{
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

	arkTx, err := buildArkTx(checkpointInputs, copiedOutputs)
	if err != nil {
		return nil, nil, err
	}

	return arkTx, checkpointTxs, nil

}

func RebuildAssetTxs(outputs []*wire.TxOut, assetGroupIndex int, checkpointTxMap map[string]string, checkpointInputs []VtxoInput, signerUnrollScript []byte) (*psbt.Packet, []*psbt.Packet, error) {

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
	resolveInputs := func(inputs []asset.AssetInput) ([]asset.AssetInput, error) {
		modifiedInputs := make([]asset.AssetInput, 0, len(inputs))
		for _, input := range inputs {

			modifiedInput, err := ReconstructAssetInput(input, checkpointTxMap)
			if err != nil {
				return nil, err
			}

			modifiedInputs = append(modifiedInputs, modifiedInput)
		}
		return modifiedInputs, nil
	}

	// If control inputs are present, find the corresponding vtxos
	for i := range controlAssets {
		inputs, err := resolveInputs(controlAssets[i].Inputs)

		if err != nil {
			return nil, nil, err
		}
		controlAssets[i].Inputs = inputs
	}

	// -------------------------
	// 2. Normal asset inputs
	// -------------------------
	for i := range normalAssets {
		inputs, err := resolveInputs(normalAssets[i].Inputs)

		if err != nil {
			return nil, nil, err
		}
		normalAssets[i].Inputs = inputs
	}

	// -------------------------
	// 3. Encode updated assetGroup and build AssetGroup Ark tx
	// -------------------------
	newAssetGroup := &asset.AssetPacket{
		ControlAssets: controlAssets,
		NormalAssets:  normalAssets,
		SubDustKey:    assetGroup.SubDustKey,
	}

	newOpretOutput, err := newAssetGroup.EncodeOpret(assetAnchor.Value)
	if err != nil {
		return nil, nil, err
	}

	outputs[assetGroupIndex] = &newOpretOutput

	return BuildAssetTxs(outputs, assetGroupIndex, checkpointInputs, signerUnrollScript)
}

func ReconstructAssetInput(assetInput asset.AssetInput, checkpointTxMap map[string]string) (asset.AssetInput, error) {
	if assetInput.Type == asset.AssetTypeTeleport {
		return assetInput, nil
	}

	moodifiedInput := assetInput

	inputTxId, err := chainhash.NewHash(assetInput.Hash)
	if err != nil {
		return asset.AssetInput{}, err
	}

	checkpointTxHex, ok := checkpointTxMap[inputTxId.String()]
	if !ok {
		return asset.AssetInput{}, fmt.Errorf("checkpoint tx not found for asset input reference %x", inputTxId)
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTxHex), true)
	if err != nil {
		return asset.AssetInput{}, err
	}

	txHash := ptx.UnsignedTx.TxHash()
	if !bytes.Equal(txHash[:], assetInput.Hash) {
		return asset.AssetInput{}, fmt.Errorf("checkpoint tx hash mismatch for asset input reference %x", inputTxId)
	}

	prev := ptx.UnsignedTx.TxIn[0].PreviousOutPoint

	moodifiedInput.Hash = prev.Hash.CloneBytes()
	moodifiedInput.Vin = uint16(prev.Index)

	return moodifiedInput, nil
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
	vtxo *VtxoInput, assetInput *asset.AssetInput, signerUnrollScript *script.CSVMultisigClosure,
) (*psbt.Packet, *VtxoInput, error) {
	if vtxo.Tapscript == nil {
		return nil, nil, fmt.Errorf("vtxo tapscript is nil")
	}

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

	var (
		checkpointPtx *psbt.Packet
	)

	if assetInput == nil {
		checkpointPtx, err = buildArkTx(
			[]VtxoInput{*vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build plain checkpoint tx: %w", err)
		}

	} else {

		var newAsset asset.AssetGroup

		newAsset.Inputs = []asset.AssetInput{
			{
				Type:   asset.AssetTypeLocal,
				Vin:    assetInput.Vin,
				Amount: assetInput.Amount,
			},
		}
		newAsset.Outputs = []asset.AssetOutput{
			{
				Type:   asset.AssetTypeLocal,
				Amount: assetInput.Amount,
				Vout:   0,
			},
		}

		// TODO (Joshua) Subdust Key is A nightmare
		newAssetGroup := &asset.AssetPacket{
			ControlAssets: nil,
			NormalAssets:  []asset.AssetGroup{newAsset},
		}

		assetOpret, err := newAssetGroup.EncodeOpret(0)
		if err != nil {
			return nil, nil, err
		}

		checkpointPtx, err = buildArkTx(
			[]VtxoInput{*vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}, &assetOpret},
		)
		if err != nil {
			return nil, nil, err
		}
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
