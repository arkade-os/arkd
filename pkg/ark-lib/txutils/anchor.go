package txutils

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	ANCHOR_PKSCRIPT = []byte{
		0x51, 0x02, 0x4e, 0x73,
	}
	ANCHOR_VALUE = int64(0)
)

func AnchorOutput() *wire.TxOut {
	return &wire.TxOut{
		Value:    ANCHOR_VALUE,
		PkScript: ANCHOR_PKSCRIPT,
	}
}

// ExtractWithAnchors extracts the final witness and scriptSig from psbt fields and ignores anchor inputs without failing.
func ExtractWithAnchors(p *psbt.Packet) (*wire.MsgTx, error) {
	finalTx := p.UnsignedTx.Copy()

	for i, tin := range finalTx.TxIn {
		pInput := p.Inputs[i]

		// ignore anchor outputs
		if pInput.WitnessUtxo != nil && bytes.Equal(pInput.WitnessUtxo.PkScript, ANCHOR_PKSCRIPT) {
			continue
		}

		if pInput.FinalScriptSig != nil {
			tin.SignatureScript = pInput.FinalScriptSig
		}

		if pInput.FinalScriptWitness != nil {
			// Read through ReadTxWitness rather than inline: the count is an
			// attacker-chosen varint and sizing a wire.TxWitness from it costs 24
			// bytes per slot, so it needs the bound that helper already applies.
			witness, err := ReadTxWitness(pInput.FinalScriptWitness)
			if err != nil {
				return nil, err
			}
			tin.Witness = witness
		}
	}

	return finalTx, nil
}

func FindAnchorOutpoint(tx *wire.MsgTx) (*wire.OutPoint, error) {
	anchorIndex := -1
	for outIndex, out := range tx.TxOut {
		if bytes.Equal(out.PkScript, ANCHOR_PKSCRIPT) {
			anchorIndex = outIndex
			break
		}
	}

	if anchorIndex == -1 {
		return nil, fmt.Errorf("anchor not found")
	}

	return &wire.OutPoint{
		Hash:  tx.TxHash(),
		Index: uint32(anchorIndex),
	}, nil
}
