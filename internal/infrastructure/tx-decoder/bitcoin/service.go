package bitcointxdecoder

import (
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
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
	for _, input := range ptx.UnsignedTx.TxIn {
		ins = append(ins, ports.TxIn{
			Txid: input.PreviousOutPoint.Hash.String(),
			VOut: input.PreviousOutPoint.Index,
		})
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
