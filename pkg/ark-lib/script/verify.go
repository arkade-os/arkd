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
)

type VerifyTapscriptOption func(*verifyTapscriptOptions)

type verifyTapscriptOptions struct {
	skipPublicKeys     []string // x-only hex encoded
	skipUnsignedInputs bool
}

// WithSkipPublicKeys sets the key to ignore in signature validation
func WithSkipPublicKeys(keys ...*btcec.PublicKey) VerifyTapscriptOption {
	return func(o *verifyTapscriptOptions) {
		encoded := make([]string, 0, len(keys))
		for _, pubkey := range keys {
			xonly := hex.EncodeToString(schnorr.SerializePubKey(pubkey))

			if slices.Contains(encoded, xonly) {
				continue // avoid duplication
			}

			encoded = append(encoded, xonly)
		}

		o.skipPublicKeys = encoded
	}
}

// WithSkipUnsignedInputs makes the func ignore unsigned inputs instead of
// returning an error.
func WithSkipUnsignedInputs() VerifyTapscriptOption {
	return func(o *verifyTapscriptOptions) {
		o.skipUnsignedInputs = true
	}
}

// VerifyTapscriptSigs verifies the tapscript signatures of the given tx.
func VerifyTapscriptSigs(
	tx *psbt.Packet, prevoutFetcher txscript.PrevOutputFetcher,
	opts ...VerifyTapscriptOption,
) (signedInputs []int, err error) {
	options := &verifyTapscriptOptions{}
	for _, opt := range opts {
		opt(options)
	}
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

			if err := executeConditionScript(inputIndex, tx, prevoutFetcher, c.Condition, witness); err != nil {
				return nil, err
			}

			for _, key := range c.PubKeys {
				// initialize to false = not signed
				expectedSigners[hex.EncodeToString(schnorr.SerializePubKey(key))] = false
			}
		case *ConditionCSVMultisigClosure:
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

			if err := executeConditionScript(inputIndex, tx, prevoutFetcher, c.Condition, witness); err != nil {
				return nil, err
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
			return nil, fmt.Errorf("invalid control block for input %d: expected tapkey %x (from prevout), got %x (computed)",
				inputIndex, expectedTaprootKey, serializedTaprootKey,
			)
		}

		// BIP341: validate the parity bit against the computed output key's Y parity.
		computedKeyIsOdd := taprootKey.SerializeCompressed()[0] == 0x03
		if controlBlock.OutputKeyYIsOdd != computedKeyIsOdd {
			return nil, fmt.Errorf(
				"invalid control block parity for input %d: expected odd=%v, got odd=%v",
				inputIndex, computedKeyIsOdd, controlBlock.OutputKeyYIsOdd,
			)
		}

		if len(input.TaprootScriptSpendSig) == 0 {
			if options.skipUnsignedInputs {
				continue
			}

			// if options.skipUnsignedInputs = false, return an error
			// only if one of the expected signer is not in skipPublicKeys
			// otherwise it means we skip all signers
			for key := range expectedSigners {
				if !slices.Contains(options.skipPublicKeys, key) {
					return nil, fmt.Errorf(
						"input %d has no tapscript signatures", inputIndex,
					)
				}
			}
			// all signers are skipped, treat input as not signed
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

		for key, hasSig := range expectedSigners {
			if slices.Contains(options.skipPublicKeys, key) {
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

func isIntent(ptx *psbt.Packet, prevFetcher txscript.PrevOutputFetcher) bool {
	if ptx.UnsignedTx.Version != 2 {
		return false
	}

	if len(ptx.UnsignedTx.TxIn) < 2 {
		return false
	}

	prevout0 := prevFetcher.FetchPrevOutput(ptx.UnsignedTx.TxIn[0].PreviousOutPoint)
	prevout1 := prevFetcher.FetchPrevOutput(ptx.UnsignedTx.TxIn[1].PreviousOutPoint)
	if prevout0 == nil || prevout1 == nil {
		return false
	}

	return bytes.Equal(prevout0.PkScript, prevout1.PkScript)
}

// we skip evaluating condition for the input 0 of intent proof.
// it is safe because we know that intent has the same on input 1.
// it avoids duplication of the witness and evaluating twice the same boolean script.
func executeConditionScript(
	inputIndex int, tx *psbt.Packet, prvFetcher txscript.PrevOutputFetcher,
	script []byte, witness wire.TxWitness,
) error {
	skip := inputIndex == 0 && isIntent(tx, prvFetcher) 
	if skip {
		return nil
	}

	result, err := EvaluateScriptToBool(script, witness)
	if err != nil {
		return err
	}
	if !result {
		return fmt.Errorf("condition not met for input %d", inputIndex)
	}
	return nil
}