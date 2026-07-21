// Package txsigner provides chain-free tapscript PSBT signing primitives shared
// by arkd-wallet, arkd-signer, and the emulator. It never fetches prevouts from
// chain: every input must already carry a WitnessUtxo.
package txsigner

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// SignTapscriptInput signs the tapscript-path input at inputIndex with signingKey
// and appends a TaprootScriptSpendSig. The input must carry a WitnessUtxo and at
// least one TaprootLeafScript.
func SignTapscriptInput(
	ptx *psbt.Packet, inputIndex int, signingKey *btcec.PrivateKey,
	sigHashes *txscript.TxSigHashes,
) error {
	if inputIndex < 0 || inputIndex >= len(ptx.Inputs) {
		return fmt.Errorf("input index %d out of range", inputIndex)
	}
	in := ptx.Inputs[inputIndex]
	if in.WitnessUtxo == nil {
		return fmt.Errorf("missing witness utxo on input %d", inputIndex)
	}
	if len(in.TaprootLeafScript) == 0 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("no taproot leaf script on input %d", inputIndex)
	}

	tapLeaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
	signature, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, sigHashes, inputIndex, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, tapLeaf, in.SighashType, signingKey,
	)
	if err != nil {
		return fmt.Errorf("failed to sign tapscript input %d: %w", inputIndex, err)
	}

	leafHash := tapLeaf.TapHash()
	ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(
		ptx.Inputs[inputIndex].TaprootScriptSpendSig,
		&psbt.TaprootScriptSpendSig{
			// drop the trailing sighash byte: it is encoded separately below
			Signature:   signature[:64],
			XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
			LeafHash:    leafHash[:],
			SigHash:     in.SighashType,
		},
	)
	return nil
}

// ExtractFinalizedTx finalizes every input and returns the hex-encoded raw tx.
// Tapscript inputs are finalized as vtxo scripts, other inputs via psbt.Finalize.
func ExtractFinalizedTx(ptx *psbt.Packet) (string, error) {
	for i, in := range ptx.Inputs {
		if in.WitnessUtxo == nil {
			return "", fmt.Errorf("missing witness utxo on input %d", i)
		}

		isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
		if isTaproot && len(in.TaprootLeafScript) > 0 {
			if err := script.FinalizeVtxoScript(ptx, i); err != nil {
				return "", err
			}
			continue
		}

		if err := psbt.Finalize(ptx, i); err != nil {
			return "", fmt.Errorf("failed to finalize input %d: %w", i, err)
		}
	}

	extracted, err := psbt.Extract(ptx)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := extracted.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}
