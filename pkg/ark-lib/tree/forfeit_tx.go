package tree

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTx(
	inputs []*wire.OutPoint, sequences []uint32, prevouts []*wire.TxOut,
	signerScript []byte, txLocktime uint32,
) (*psbt.Packet, error) {

	sumPrevout := int64(0)
	for _, prevout := range prevouts {
		sumPrevout += prevout.Value
	}
	sumPrevout -= txutils.ANCHOR_VALUE

	forfeitOut := wire.NewTxOut(sumPrevout, signerScript)
	return BuildForfeitTxWithOutput(inputs, sequences, prevouts, forfeitOut, txLocktime)
}

func BuildForfeitTxWithOutput(
	inputs []*wire.OutPoint, sequences []uint32, prevouts []*wire.TxOut,
	forfeitOutput *wire.TxOut,
	txLocktime uint32,
) (*psbt.Packet, error) {
	version := int32(3)
	outs := []*wire.TxOut{forfeitOutput, txutils.AnchorOutput()}

	partialTx, err := psbt.New(
		inputs,
		outs,
		version,
		txLocktime,
		sequences,
	)
	if err != nil {
		return nil, err
	}

	updater, err := psbt.NewUpdater(partialTx)
	if err != nil {
		return nil, err
	}

	for i, prevout := range prevouts {
		if err := updater.AddInWitnessUtxo(prevout, i); err != nil {
			return nil, err
		}
	}

	return partialTx, nil
}
