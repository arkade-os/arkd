package txutils

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
			witnessReader := bytes.NewReader(
				pInput.FinalScriptWitness,
			)

			witCount, err := wire.ReadVarInt(witnessReader, 0)
			if err != nil {
				return nil, err
			}

			tin.Witness = make(wire.TxWitness, witCount)
			for j := uint64(0); j < witCount; j++ {
				wit, err := wire.ReadVarBytes(
					witnessReader, 0,
					txscript.MaxScriptSize, "witness",
				)
				if err != nil {
					return nil, err
				}
				tin.Witness[j] = wit
			}
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
