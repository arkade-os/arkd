package tree

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

const (
	// signal CLTV with input sequence number
	cltvSequence = wire.MaxTxInSequenceNum - 1
)

// BuildOffchainTx builds an offchain tx for the given vtxos and outputs.
// it also builds the checkpoint txs for each input vtxo.
func BuildOffchainTx(
	vtxos []common.VtxoInput, outputs []*wire.TxOut,
	serverUnrollScript *CSVMultisigClosure,
) (*psbt.Packet, []*psbt.Packet, error) {
	checkpointsInputs := make([]common.VtxoInput, 0, len(vtxos))
	checkpointsTxs := make([]*psbt.Packet, 0, len(vtxos))

	inputAmount := int64(0)

	for _, vtxo := range vtxos {
		checkpointPtx, checkpointInput, err := buildCheckpointTx(vtxo, serverUnrollScript)
		if err != nil {
			return nil, nil, err
		}

		checkpointsInputs = append(checkpointsInputs, checkpointInput)
		checkpointsTxs = append(checkpointsTxs, checkpointPtx)
		inputAmount += vtxo.Amount
	}

	outputAmount := int64(0)
	for _, output := range outputs {
		outputAmount += output.Value
	}

	if inputAmount != outputAmount {
		return nil, nil, fmt.Errorf("input amount is not equal to output amount")
	}

	virtualPtx, err := buildVirtualTx(checkpointsInputs, outputs)
	if err != nil {
		return nil, nil, err
	}

	return virtualPtx, checkpointsTxs, nil
}

// buildVirtualTx builds a virtual tx for the given vtxos and outputs.
// The virtual tx is spending VTXOs using collaborative taproot path.
// An anchor output is added to the transaction
func buildVirtualTx(
	vtxos []common.VtxoInput,
	outputs []*wire.TxOut,
) (*psbt.Packet, error) {
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
		taprootKey := txscript.ComputeTaprootOutputKey(UnspendableKey(), rootHash)

		vtxoOutputScript, err := common.P2TRScript(taprootKey)
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

		closure, err := DecodeClosure(vtxo.Tapscript.RevealedScript)
		if err != nil {
			return nil, err
		}

		// check if the closure is a CLTV multisig closure,
		// if so, update the tx locktime
		var locktime *common.AbsoluteLocktime
		if cltv, ok := closure.(*CLTVMultisigClosure); ok {
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

	virtualPtx, err := psbt.New(
		ins, append(outputs, AnchorOutput()), 3, uint32(txLocktime), sequences,
	)
	if err != nil {
		return nil, err
	}

	for i := range virtualPtx.Inputs {
		virtualPtx.Inputs[i].WitnessUtxo = witnessUtxos[i]
		virtualPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{signingTapLeaves[i]}
		if err := AddTaprootTree(i, virtualPtx, tapscripts[i]); err != nil {
			return nil, err
		}
	}

	return virtualPtx, nil
}

// buildCheckpointTx creates a virtual tx sending to a "checkpoint" vtxo script composed of
// the server unroll script + the owner's collaborative closure.
func buildCheckpointTx(vtxo common.VtxoInput, serverUnrollScript *CSVMultisigClosure) (*psbt.Packet, common.VtxoInput, error) {
	// create the checkpoint vtxo script from collaborative closure
	checkpointCollaborativeTapscript := vtxo.Tapscript
	if vtxo.CheckpointTapscript != nil {
		checkpointCollaborativeTapscript = vtxo.CheckpointTapscript
	}

	collaborativeClosure, err := DecodeClosure(checkpointCollaborativeTapscript.RevealedScript)
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	checkpointVtxoScript := TapscriptsVtxoScript{
		[]Closure{serverUnrollScript, collaborativeClosure},
	}

	tapKey, tapTree, err := checkpointVtxoScript.TapTree()
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	checkpointPkScript, err := common.P2TRScript(tapKey)
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	// build the checkpoint virtual tx
	checkpointPtx, err := buildVirtualTx(
		[]common.VtxoInput{vtxo},
		[]*wire.TxOut{{Value: vtxo.Amount, PkScript: checkpointPkScript}},
	)
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	// now that we have the checkpoint tx, we need to return the corresponding output that will be used as input for the virtual tx
	tapLeafHash := txscript.NewBaseTapLeaf(checkpointCollaborativeTapscript.RevealedScript).TapHash()
	collaborativeLeafProof, err := tapTree.GetTaprootMerkleProof(tapLeafHash)
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	ctrlBlock, err := txscript.ParseControlBlock(collaborativeLeafProof.ControlBlock)
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	revealedTapscripts, err := checkpointVtxoScript.Encode()
	if err != nil {
		return nil, common.VtxoInput{}, err
	}

	checkpointInput := common.VtxoInput{
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
