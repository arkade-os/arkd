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

// ForfeitTxReadyToBroadcast reports whether a forfeit psbt carries every
// signature its finalizer needs. It checks presence, not validity: a signature
// counts when it is under a pubkey the leaf commits to and over that same leaf.
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
// carries a signature only the operator can produce: a tapscript spend sig under
// one of operatorXOnlyKeys, or a key spend sig on any input.
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
