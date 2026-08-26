package tree

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

// BuildLegacySweepTapTreeRoot returns the sweep tapscript root for a batch using
// the relative-CSV expiry scheme, along with the leaf script itself.
//
// Every batch built before epoch expiry uses this, and it must keep producing
// byte-identical output forever: it is what lets the operator sweep trees
// created by older releases, and what lets a client re-derive and verify the
// taproot output key of every node in a tree it is asked to sign.
func BuildLegacySweepTapTreeRoot(
	operator *btcec.PublicKey, expiry arklib.RelativeLocktime,
) (chainhash.Hash, []byte, error) {
	leafScript, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{operator}},
		Locktime:        expiry,
	}).Script()
	if err != nil {
		return chainhash.Hash{}, nil, err
	}

	return txscript.NewBaseTapLeaf(leafScript).TapHash(), leafScript, nil
}

// BuildEpochSweepTapTreeRoot returns the sweep tapscript root for an epoch batch:
// an absolute expiry date shared across the epoch, plus a relative grace period
// that only bites for outputs created by a mid-flight unilateral unroll.
func BuildEpochSweepTapTreeRoot(
	operator *btcec.PublicKey,
	expiryDate arklib.AbsoluteLocktime,
	grace arklib.RelativeLocktime,
) (chainhash.Hash, []byte, error) {
	leafScript, err := (&script.CLTVCSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{operator}},
		ExpiryDate:      expiryDate,
		UnrollGrace:     grace,
	}).Script()
	if err != nil {
		return chainhash.Hash{}, nil, err
	}

	return txscript.NewBaseTapLeaf(leafScript).TapHash(), leafScript, nil
}
