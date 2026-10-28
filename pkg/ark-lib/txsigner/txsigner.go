// Package txsigner signs and finalizes PSBTs without chain access: every input
// must carry a WitnessUtxo.
package txsigner

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

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

	if err := script.CheckSigHashType(in.SighashType); err != nil {
		return fmt.Errorf("input %d: %w", inputIndex, err)
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
			Signature:   signature[:64],
			XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
			LeafHash:    leafHash[:],
			SigHash:     in.SighashType,
		},
	)
	return nil
}

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
