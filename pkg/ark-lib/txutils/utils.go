package txutils

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func ReadTxWitness(witnessSerialized []byte) (wire.TxWitness, error) {
	r := bytes.NewReader(witnessSerialized)

	// first we extract the number of witness elements
	witCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	remainingBytes := r.Len()
	// Each witness item needs at least a 1-byte length prefix, so count cannot exceed remaining bytes.
	if witCount > uint64(remainingBytes) {
		return nil, fmt.Errorf("invalid witness count: %d exceeds remaining bytes: %d", witCount, remainingBytes)
	}

	// read each witness item
	witness := make(wire.TxWitness, witCount)
	for i := range witCount {
		witness[i], err = wire.ReadVarBytes(r, 0, txscript.MaxScriptSize, "witness")
		if err != nil {
			return nil, err
		}
	}

	return witness, nil
}

// GetPrevOutputFetcher computes a prevout fetcher from WitnessUtxo fields
func GetPrevOutputFetcher(tx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range tx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("missing witness utxo on input #%d", i)
		}

		outpoint := tx.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}
