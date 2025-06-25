package tree

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTx(
	inputs []*wire.OutPoint,
	sequences []uint32,
	prevouts []*wire.TxOut,
	serverScript []byte,
	txLocktime uint32,
) (*psbt.Packet, error) {
	version := int32(3)

	sumPrevout := int64(0)
	for _, prevout := range prevouts {
		sumPrevout += prevout.Value
	}
	sumPrevout -= ANCHOR_VALUE

	outs := []*wire.TxOut{
		{
			Value:    sumPrevout,
			PkScript: serverScript,
		},
		AnchorOutput(),
	}

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

		if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
			return nil, err
		}
	}

	return partialTx, nil
}
