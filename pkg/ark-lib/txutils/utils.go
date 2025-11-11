package txutils

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var unspendablePoint = []byte{
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
	0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}
var unspendableKey, _ = btcec.ParsePubKey(unspendablePoint)

func ReadTxWitness(witnessSerialized []byte) (wire.TxWitness, error) {
	r := bytes.NewReader(witnessSerialized)

	// first we extract the number of witness elements
	witCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
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

// VerifyTapscriptSigs verifies the tapscript signatures of the given tx
// it skips inputs that are not signed or do not specify a taproot leaf script
func VerifyTapscriptSigs(tx *psbt.Packet, prevoutFetcher txscript.PrevOutputFetcher) (signedInputs []int, err error) {
	if len(tx.Inputs) != len(tx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf(
			"malformed tx: number of psbt inputs (%d) does not match number of tx inputs (%d)",
			len(tx.Inputs), len(tx.UnsignedTx.TxIn),
		)
	}

	txSigHashes := txscript.NewTxSigHashes(tx.UnsignedTx, prevoutFetcher)

	signedInputs = make([]int, 0, len(tx.Inputs))

	for inputIndex, input := range tx.Inputs {
		// skip if does not specify a taproot leaf script
		if len(input.TaprootLeafScript) != 1 {
			continue
		}

		prevout := prevoutFetcher.FetchPrevOutput(tx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint)
		if prevout == nil {
			return nil, fmt.Errorf("prevout %s not found (input index: %d)",
				tx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.String(), inputIndex,
			)
		}

		// skip if not a taproot input
		if txscript.GetScriptClass(prevout.PkScript) != txscript.WitnessV1TaprootTy {
			continue
		}

		tapscriptLeaf := input.TaprootLeafScript[0]

		// taproot leaf script must match the witness utxo pkscript
		var controlBlock *txscript.ControlBlock
		controlBlock, err = txscript.ParseControlBlock(tapscriptLeaf.ControlBlock)
		if err != nil {
			return nil, fmt.Errorf("failed to parse control block for input %d: %s", inputIndex, err)
		}

		rootHash := controlBlock.RootHash(tapscriptLeaf.Script)
		taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, rootHash[:])
		serializedTaprootKey := schnorr.SerializePubKey(taprootKey)
		expectedTaprootKey := prevout.PkScript[2:]

		if !bytes.Equal(serializedTaprootKey, expectedTaprootKey) {
			return nil, fmt.Errorf("invalid control block for input %d: expected tapkey %x, got %x",
				inputIndex, serializedTaprootKey, expectedTaprootKey,
			)
		}

		// skip if not signed
		if len(input.TaprootScriptSpendSig) == 0 {
			continue
		}

		leaf := txscript.NewBaseTapLeaf(tapscriptLeaf.Script)
		leafHash := leaf.TapHash()

		for i, tapscriptSig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(tapscriptSig.LeafHash, leafHash[:]) {
				return nil, fmt.Errorf("invalid leaf hash for tapscript sig %d of input %d: expected %x, got %x",
					i, inputIndex, leafHash[:], tapscriptSig.LeafHash,
				)
			}

			var sighash []byte
			sighash, err = txscript.CalcTapscriptSignaturehash(
				txSigHashes,
				txscript.SigHashDefault,
				tx.UnsignedTx,
				inputIndex,
				prevoutFetcher,
				leaf,
			)
			if err != nil {
				return
			}

			var sig *schnorr.Signature
			sig, err = schnorr.ParseSignature(tapscriptSig.Signature)
			if err != nil {
				return
			}

			var pubkey *btcec.PublicKey
			pubkey, err = schnorr.ParsePubKey(tapscriptSig.XOnlyPubKey)
			if err != nil {
				return
			}

			if !sig.Verify(sighash, pubkey) {
				return nil, fmt.Errorf(
					"invalid signature (%d) for input %s",
					i, tx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.String(),
				)
			}
		}

		signedInputs = append(signedInputs, inputIndex)
	}

	return
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
