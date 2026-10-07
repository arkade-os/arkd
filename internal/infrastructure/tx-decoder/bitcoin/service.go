package bitcointxdecoder

import (
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/psbt/v2"
)

type service struct{}

func NewService() ports.TxDecoder {
	return &service{}
}

func (s *service) DecodeTx(tx string) (string, []ports.TxIn, []ports.TxOut, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse partial tx: %s", err)
	}

	txid := ptx.UnsignedTx.TxID()
	ins := make([]ports.TxIn, 0, len(ptx.UnsignedTx.TxIn))
	for i, input := range ptx.UnsignedTx.TxIn {
		in := ports.TxIn{
			Outpoint: domain.Outpoint{
				Txid: input.PreviousOutPoint.Hash.String(),
				VOut: input.PreviousOutPoint.Index,
			},
		}
		// Not every tx carries its prevouts, vtxo tree txs don't: callers needing them must
		// check for nil.
		if i < len(ptx.Inputs) && ptx.Inputs[i].WitnessUtxo != nil {
			in.Prevout = &ports.TxOut{
				Amount:   uint64(ptx.Inputs[i].WitnessUtxo.Value),
				PkScript: ptx.Inputs[i].WitnessUtxo.PkScript,
			}
		}
		ins = append(ins, in)
	}
	outs := make([]ports.TxOut, 0, len(ptx.UnsignedTx.TxOut))
	for _, output := range ptx.UnsignedTx.TxOut {
		outs = append(outs, ports.TxOut{
			Amount:   uint64(output.Value),
			PkScript: output.PkScript,
		})
	}
	return txid, ins, outs, nil
}
