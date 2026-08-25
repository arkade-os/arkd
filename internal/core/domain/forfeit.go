package domain

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// ForfeitTxReadyToBroadcast reports whether a forfeit psbt already carries every
// signature its finalizer needs, so it can be broadcast without calling the
// signer. A forfeit spends two inputs: the vtxo, through a tapscript leaf, and
// the connector, through the wallet key path.
//
// Readiness is keyed on the pubkeys the leaf itself commits to, not on the
// operator's current signer key. A forfeit signed before a signer-key rotation
// therefore stays recognized as ready, which is the property collection-time
// signing exists to provide: the stored forfeit must remain broadcastable even
// once the key that signed it is no longer the current one.
//
// A signature counts only when it is under a pubkey the leaf commits to and over
// that same leaf. This still reports what the psbt carries, not whether those
// signatures cryptographically verify, and not whether a condition closure's
// witness is present. Presence is enough because SubmitForfeitTxs rejects a
// forfeit that arrives already carrying an operator signature, so the only one a
// stored forfeit holds is arkd's own.
func ForfeitTxReadyToBroadcast(ptx *psbt.Packet) bool {
	if len(ptx.Inputs) <= 0 {
		return false
	}

	for _, in := range ptx.Inputs {
		// key path (the connector): the wallet key spend sig is all it needs
		if len(in.TaprootLeafScript) <= 0 {
			if len(in.TaprootKeySpendSig) <= 0 {
				return false
			}
			continue
		}

		// script path (the vtxo): one sig per pubkey the leaf closure commits to
		pubkeys, err := forfeitLeafPubkeys(in.TaprootLeafScript[0].Script)
		if err != nil || len(pubkeys) <= 0 {
			return false
		}

		// A tapscript sig is valid only for the script it was made over, which the
		// psbt records as its leaf hash. One vtxo can expose several forfeit
		// closures that all carry the operator key, so matching on pubkey alone
		// would accept a sig made for a sibling leaf and fail at finalization.
		leafHash := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script).TapHash()
		signed := make(map[string]struct{}, len(in.TaprootScriptSpendSig))
		for _, sig := range in.TaprootScriptSpendSig {
			if !bytes.Equal(sig.LeafHash, leafHash[:]) {
				continue
			}
			signed[string(sig.XOnlyPubKey)] = struct{}{}
		}
		for _, pubkey := range pubkeys {
			if _, ok := signed[string(schnorr.SerializePubKey(pubkey))]; !ok {
				return false
			}
		}
	}

	return true
}

// ForfeitTxCarriesOperatorSignature reports whether a submitted forfeit psbt
// already carries a signature only the operator can produce: a tapscript spend
// sig under one of operatorXOnlyKeys, or a key spend sig on any input, which on a
// forfeit can only be the connector the operator's wallet owns.
//
// A client has no way to produce either, so carrying one is always an attempt to
// plant a signature rather than an honest submission.
func ForfeitTxCarriesOperatorSignature(ptx *psbt.Packet, operatorXOnlyKeys [][]byte) bool {
	for _, in := range ptx.Inputs {
		if len(in.TaprootKeySpendSig) > 0 {
			return true
		}
		for _, sig := range in.TaprootScriptSpendSig {
			for _, key := range operatorXOnlyKeys {
				// an unset operator key must not match an unset sig key
				if len(key) > 0 && bytes.Equal(sig.XOnlyPubKey, key) {
					return true
				}
			}
		}
	}
	return false
}

// forfeitLeafPubkeys returns the pubkeys the forfeit leaf closure requires a
// signature from. Forfeit closures are always multisig.
func forfeitLeafPubkeys(leafScript []byte) ([]*btcec.PublicKey, error) {
	closure, err := script.DecodeClosure(leafScript)
	if err != nil {
		return nil, err
	}

	switch c := closure.(type) {
	case *script.MultisigClosure:
		return c.PubKeys, nil
	case *script.CLTVMultisigClosure:
		return c.PubKeys, nil
	case *script.ConditionMultisigClosure:
		return c.PubKeys, nil
	}
	return nil, fmt.Errorf("unexpected forfeit closure type %T", closure)
}
