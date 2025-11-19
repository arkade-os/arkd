package offchain

import (
	"bytes"
	"fmt"

	common "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
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

	var assetData *asset.Asset
	var batchId []byte
	var assetOpretIndex int

	newAssetInputs := make([]asset.AssetInput, 0, len(outputs))

	for i, out := range outputs {
		assetData, batchId, err = asset.DecodeAssetFromOpret(out.PkScript)
		if err == nil {
			assetOpretIndex = i
			break
		}
	}

	if assetData != nil {
		for _, vtxo := range vtxos {
			checkpointPtx, checkpointInput, assetOutput, err := buildAssetCheckpointTx(vtxo, assetData, batchId, signerUnrollScriptClosure)
			if err != nil {
				return nil, nil, err
			}

			if assetOutput != nil {
				txId := checkpointPtx.UnsignedTx.TxHash()
				newAssetInputs = append(newAssetInputs, asset.AssetInput{
					Txid:   txId[:],
					Vout:   0,
					Amount: assetOutput.Amount,
				})
			}

			checkpointInputs = append(checkpointInputs, *checkpointInput)
			checkpointTxs = append(checkpointTxs, checkpointPtx)
			inputAmount += vtxo.Amount
		}

		newAsset := *assetData
		newAsset.Inputs = newAssetInputs

		newOpretOutput, err := newAsset.EncodeOpret(batchId)
		if err != nil {
			return nil, nil, err
		}

		outputs[assetOpretIndex] = &newOpretOutput
	} else {
		for _, vtxo := range vtxos {
			checkpointPtx, checkpointInput, err := buildCheckpointTx(vtxo, signerUnrollScriptClosure)
			if err != nil {
				return nil, nil, err
			}

			checkpointInputs = append(checkpointInputs, *checkpointInput)
			checkpointTxs = append(checkpointTxs, checkpointPtx)
			inputAmount += vtxo.Amount
		}
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

func buildAssetCheckpointTx(
	vtxo VtxoInput, arkAsset *asset.Asset, batchId []byte, signerUnrollScript *script.CSVMultisigClosure,
) (*psbt.Packet, *VtxoInput, *asset.AssetOutput, error) {
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

	newAsset := *arkAsset

	var isSeal bool

	for _, input := range newAsset.Inputs {
		if bytes.Equal(input.Txid, vtxo.Outpoint.Hash[:]) && input.Vout == vtxo.Outpoint.Index {
			isSeal = true
			newAsset.Inputs = []asset.AssetInput{
				{
					Txid: vtxo.Outpoint.Hash[:],
					Vout: vtxo.Outpoint.Index,
				},
			}
			newAsset.Outputs = []asset.AssetOutput{
				{
					PublicKey: *tapKey,
					Amount:    input.Amount,
					Vout:      0,
				},
			}
			break
		}
	}

	var checkpointPtx *psbt.Packet

	if !isSeal {
		checkpointPtx, err = buildArkTx(
			[]VtxoInput{vtxo}, []*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}},
		)
		if err != nil {
			return nil, nil, nil, err
		}

	} else {
		assetOpret, err := newAsset.EncodeOpret(batchId[:])
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

	if isSeal {
		return checkpointPtx, checkpointInput, &newAsset.Outputs[0], nil
	}

	return checkpointPtx, checkpointInput, nil, nil

}
