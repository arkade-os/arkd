package script

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// FinalizeVtxoScript finalizes the given input as vtxo script IF the witness utxo is a decodable vtxo script closure.
func FinalizeVtxoScript(ptx *psbt.Packet, inputIndex int) error {
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	in := ptx.Inputs[inputIndex]

	closure, err := DecodeClosure(in.TaprootLeafScript[0].Script)
	if err != nil {
		return err
	}

	arkConditionWitnessFields, err := txutils.GetArkPsbtFields(ptx, inputIndex, txutils.ConditionWitnessField)
	if err != nil {
		return err
	}

	args := make(map[string][]byte)
	if len(arkConditionWitnessFields) > 0 {
		var conditionWitnessBytes bytes.Buffer
		if err := psbt.WriteTxWitness(
			&conditionWitnessBytes, arkConditionWitnessFields[0],
		); err != nil {
			return err
		}
		args[string(txutils.ArkFieldConditionWitness)] = conditionWitnessBytes.Bytes()
	}

	for _, sig := range in.TaprootScriptSpendSig {
		args[hex.EncodeToString(sig.XOnlyPubKey)] = EncodeTaprootSignature(
			sig.Signature,
			sig.SigHash,
		)
	}

	witness, err := closure.Witness(in.TaprootLeafScript[0].ControlBlock, args)
	if err != nil {
		return err
	}

	var witnessBuf bytes.Buffer
	if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
		return err
	}

	ptx.Inputs[inputIndex].FinalScriptWitness = witnessBuf.Bytes()

	return nil
}
