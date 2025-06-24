package tree

import (
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildForfeitTx(
	vtxoInput, connectorInput *wire.OutPoint,
	vtxoPrevout, connectorPrevout *wire.TxOut,
	serverScript []byte,
	txLocktime uint32,
	vtxoFirst bool,
) (*psbt.Packet, error) {
	version := int32(3)

	outs := []*wire.TxOut{
		{
			Value:    vtxoPrevout.Value + connectorPrevout.Value,
			PkScript: serverScript,
		},
		AnchorOutput(),
	}

	vtxoSequence := wire.MaxTxInSequenceNum
	if txLocktime != 0 {
		vtxoSequence = wire.MaxTxInSequenceNum - 1
	}

	connectorInputIndex := 0
	vtxoInputIndex := 1

	inputs := []*wire.OutPoint{connectorInput, vtxoInput}
	sequences := []uint32{wire.MaxTxInSequenceNum, vtxoSequence}
	if vtxoFirst {
		inputs = []*wire.OutPoint{vtxoInput, connectorInput}
		sequences = []uint32{vtxoSequence, wire.MaxTxInSequenceNum}
		connectorInputIndex = 1
		vtxoInputIndex = 0
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

	if err := updater.AddInWitnessUtxo(connectorPrevout, connectorInputIndex); err != nil {
		return nil, err
	}

	if err := updater.AddInWitnessUtxo(vtxoPrevout, vtxoInputIndex); err != nil {
		return nil, err
	}

	// add sighash DEFAUlT
	for i := range inputs {
		if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
			return nil, err
		}
	}

	return partialTx, nil
}
