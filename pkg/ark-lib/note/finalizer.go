package note

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

var ErrInvalidNoteScript = fmt.Errorf("invalid not script")

// FinalizeNoteClosure builds and sets the final witness for a note closure input.
func FinalizeNoteClosure(ptx *psbt.Packet, inputIndex int, tapleaf *psbt.TaprootTapLeafScript) error {
	var noteClosure NoteClosure
	valid, err := noteClosure.Decode(tapleaf.Script)
	if valid && err == nil {
		conditionWitness, err := txutils.GetArkPsbtConditionWitness(ptx, inputIndex)
		if err != nil {
			return err
		}

		if len(conditionWitness) == 0 {
			return fmt.Errorf("invalid condition witness, expected 1 witness for note vtxo")
		}

		witness, err := noteClosure.Witness(tapleaf.ControlBlock, map[string][]byte{
			"preimage": conditionWitness[0],
		})
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

	return ErrInvalidNoteScript
}