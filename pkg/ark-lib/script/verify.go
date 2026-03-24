package script

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// VerifyTapscriptSigs verifies the tapscript signatures of the given tx
// it skips inputs that are not signed or do not specify a taproot leaf script
func VerifyTapscriptSigs(tx *psbt.Packet, prevoutFetcher txscript.PrevOutputFetcher, skip []*secp256k1.PublicKey) (signedInputs []int, err error) {
	if len(tx.Inputs) != len(tx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf(
			"malformed tx: number of psbt inputs (%d) does not match number of tx inputs (%d)",
			len(tx.Inputs), len(tx.UnsignedTx.TxIn),
		)
	}

	txSigHashes := txscript.NewTxSigHashes(tx.UnsignedTx, prevoutFetcher)

	signedInputs = make([]int, 0, len(tx.Inputs))

	unspendableKey := UnspendableKey()

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

		// ignore notes (OP_SHA256 <32-byte hash> OP_EQUAL)
		if IsNoteClosureScript(tapscriptLeaf.Script) {
			continue
		}

		closure, err := DecodeClosure(input.TaprootLeafScript[0].Script)
		if err != nil {
			return nil, err
		}

		expectedSigners := make(map[string]bool)

		switch c := closure.(type) {
		case *MultisigClosure:
			for _, key := range c.PubKeys {
				expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *CSVMultisigClosure:
			for _, key := range c.PubKeys {
				expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *CLTVMultisigClosure:
			for _, key := range c.PubKeys {
				expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *ConditionMultisigClosure:
			witnessFields, err := txutils.GetArkPsbtFields(
				tx, inputIndex, txutils.ConditionWitnessField,
			)
			if err != nil {
				return nil, err
			}
			witness := make(wire.TxWitness, 0)
			if len(witnessFields) > 0 {
				witness = witnessFields[0]
			}

			result, err := EvaluateScriptToBool(c.Condition, witness)
			if err != nil {
				return nil, err
			}

			if !result {
				return nil, fmt.Errorf("condition not met for input %d", inputIndex)
			}

			for _, key := range c.PubKeys {
				// initialize to false = not signed
				expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		}

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

			sigHashType := tapscriptSig.SigHash
			if sigHashType == 0 {
				sigHashType = txscript.SigHashDefault
			}

			var sighash []byte
			sighash, err = txscript.CalcTapscriptSignaturehash(
				txSigHashes,
				sigHashType,
				tx.UnsignedTx,
				inputIndex,
				prevoutFetcher,
				leaf,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to compute hash for signature %d of input %d: %w", i, inputIndex, err,
				)
			}

			var sig *schnorr.Signature
			sig, err = schnorr.ParseSignature(tapscriptSig.Signature)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to parse signature %d for input %d: %w", i, inputIndex, err,
				)
			}

			var pubkey *btcec.PublicKey
			pubkey, err = schnorr.ParsePubKey(tapscriptSig.XOnlyPubKey)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to parse pubkey of sig %d for input %d: %w", i, inputIndex, err,
				)
			}

			if !sig.Verify(sighash, pubkey) {
				return nil, fmt.Errorf(
					"invalid sig %d for input %d with prevout %s",
					i, inputIndex, tx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint,
				)
			}

			expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(pubkey))] = true
		}

		signedInputs = append(signedInputs, inputIndex)

		ignore := make([]string, 0, len(skip))
		for _, pubkey := range skip {
			ignore = append(ignore, hex.EncodeToString(schnorr.SerializePubKey(pubkey)))
		}

		for key, hasSig := range expectedSigners {
			if slices.Contains(ignore, key) {
				continue
			}

			if !hasSig {
				return nil, fmt.Errorf("missing signature for %s", key)
			}
		}
	}

	return
}

// IsNoteClosureScript returns true if the script is a note closure: OP_SHA256 <32 bytes> OP_EQUAL.
func IsNoteClosureScript(script []byte) bool {
	return len(script) == 35 &&
		script[0] == txscript.OP_SHA256 &&
		script[1] == txscript.OP_DATA_32 &&
		script[34] == txscript.OP_EQUAL
}
